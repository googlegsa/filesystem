// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.fs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.Sets;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.StartupException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

// TODO(mifern): Support\Verify that we can handle \\host\C$ shares.
// TODO(mifern): Support\Verify that we can handle \\host only shares.
// TODO(mifern): Decide what we want to discover within \\host only shares.
/**
 * Runs on Microsoft Windows and serves files from networked shares.
 * <p>
 * Features:<br>
 * <ul>
 * <li>Supports UNC path to single machine's share, such as \\host\share
 * <li>Supports UNC path to standalone or domain-based DFS namespace,
 *     such as \\dfs-server\namespace or \\domain-dfs-server\namespace and
 *     will follow all the DFS links within that namespace
 * <li>Supports UNC path to standalone or domain-based DFS link, such as
 *     \\dfs-server\namespace\link or \\domain-dfs-server\namespace\link
 * <li>Uses hierarchical ACL model
 * </ul>
 * <p>
 * This adaptor attempts to replicate the Windows file system ACL inheritance
 * model in a manner the GSA can apply.  All ACLs, including those from a 
 * DFS server, network share, and the file system are supplied as named
 * resources at crawl time in {@link #getDocContent}. The resource names are
 * a combination of the DocId of the item being crawled and a "fragment"
 * identifying the type of ACL that the named resource value contains.
 * <p>
 * Windows permission inheritance has many nuances:
 * <ul>
 * <li>Generally, files and folders inherit permissions from their parent
 *     folder.
 * <li>Files and folders may also have explicit permissions that enhance
 *     or reduce permissions inherited from their parent.
 * <li>A file or folder can be configured to not inherit any permissions from
 *     its parent.
 * <li>A folder can have permissions that apply only to itself and child
 *     folders.
 * <li>A folder can have permissions that apply only to child files.
 * <li>A folder can have permissions that do not apply to itself, but
 *     do apply to its children.
 * <li>A folder can have permissions that applies to itself, but
 *     does apply to any of its children.
 * <li>A folder can have permissions that applies only to its direct children,
 *     but none of their descendants.
 * </ul>
 * For more details, see {@link AclBuilder}.
 * <p>
 * To model these various behaviors, folders typically supply four separate
 * ACLs as named resources used for inheritance purposes:
 * <ul>
 * <li>{@code ALL_FOLDER_INHERIT_ACL}: Permissions inheritable by all
 *     descendent folders.
 * <li>{@code ALL_FILE_INHERIT_ACL}: Permissions inheritable by all
 *     descendent regular files.
 * <li>{@code CHILD_FOLDER_INHERIT_ACL}: Permissions inheritable only by
 *     direct child folders, but no other descendent folders.
 * <li>{@code CHILD_FILE_INHERIT_ACL}: Permissions inheritable only by
 *     direct child files, but no other descendent regular files.
 * </ul>
 * Folders and regular files also supply their own specific ACL, which contains
 * any explicit permissions set on that item. Usually, this ACL is empty
 * and simply inherits from one of its parent's four inheritable ACLs.
 * <p>
 * File system ACLs are not the only ACLs supplied the the GSA. Windows shares
 * and DFS links also gate access to the file system, so their permissions must
 * be considered as well.
 * <p>
 * The Share ACL is used by the system to control access to the network
 * share and usually presents itself as a username/password prompt when the
 * user attempts to mount the network file system. The SHARE_ACL is supplied
 * as a named resource when the root of the shared folder is crawled, in
 * addition to the four inheritable named resources. The file share may be an
 * explicit network share supplied as a start path, or it may be the target of
 * a DFS link (see below). The root of the share (the folder that was made
 * sharable) inherits from the SHARE_ACL, not its parent folder. Note that
 * the user must be  permitted by the Share ACL <em>AND</em> the file system
 * ACL to be granted access to an item.
 * <p>
 * In 2003, Microsoft rolled out Distributed File System (DFS). A typical
 * DFS configuration consists of one or more <em>Namespaces</em>. Each
 * Namespace contains one or more <em>Links</em>. Each Link redirects to one
 * or more <em>Targets</em>. Targets are network shared folders. Users
 * generally access a single Target. The others are often used for
 * replication and fail-over. The DFS configuration may be stored on a
 * domain controller such as Active Directory, in which case it is known as
 * a <em>Domain-based</em> DFS configuration.
 * DFS configuration hosted by a member server, rather than the domain
 * controller, is known as a <em>Stand-alone</em> DFS configuration.
 * Note that from the point of view of this adaptor, we do not distinguish
 * between Domain-based and Stand-alone DFS.
 * <p>
 * The DFS system employs access control when navigating its links,
 * and usually each DFS Link has its own ACL. One of the more exotic
 * mechanisms employed by this is <em>Access-based Enumeration</em> (ABE).
 * With ABE deployed, users may only see a subset of the DFS Links, possibly
 * only one when ABE is used to isolate hosted home directories.
 * When traversing a DFS system, this adaptor supplies the DFS Link ACL,
 * in addition to the target's Share ACL as a named resource when the
 * DFS Link is crawled. In this case, the Share ACL inherits from the
 * DFS ACL. The user must be permitted by the DFS ACL <em>AND</em> the Share
 * ACL <em>AND</em> the file system ACL to be granted access to an item.
 * <p>
 * Note: If the DFS system employs Access-based Enumeration, make sure
 * the traversal user has sufficient permissions to see all the links
 * that require indexing.
 */
public class FsAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(FsAdaptor.class.getName());

  /** The config parameter name for the root path. */
  private static final String CONFIG_SRC = "filesystemadaptor.src";

  /** The config parameter name for the supported Windows accounts. */
  private static final String CONFIG_SUPPORTED_ACCOUNTS =
      "filesystemadaptor.supportedAccounts";

  /** The config parameter name for turning on/off hidden file indexing. */
  private static final String CONFIG_CRAWL_HIDDEN_FILES =
      "filesystemadaptor.crawlHiddenFiles";    

  /** Relative config parameter name for earliest last accessed time allowed. */
  private static final String CONFIG_LAST_ACCESSED_DAYS =
      "filesystemadaptor.lastAccessedDays";
 
  /** Absolute config parameter name for earliest last accessed time allowed. */
  private static final String CONFIG_LAST_ACCESSED_DATE =
      "filesystemadaptor.lastAccessedDate";

  /** Relative config parameter name for earliest last modified time allowed. */
  private static final String CONFIG_LAST_MODIFIED_DAYS =
      "filesystemadaptor.lastModifiedDays";

  /** Absolute config parameter name for earliest last modified time allowed. */
  private static final String CONFIG_LAST_MODIFIED_DATE =
      "filesystemadaptor.lastModifiedDate";

  /** Fragements used for creating the inherited ACL named resources. */
  private static final String ALL_FOLDER_INHERIT_ACL = "allFoldersAcl";
  private static final String ALL_FILE_INHERIT_ACL = "allFilesAcl";
  private static final String CHILD_FOLDER_INHERIT_ACL = "childFoldersAcl";
  private static final String CHILD_FILE_INHERIT_ACL = "childFilesAcl";

  /** Fragement used for creating the DFS share ACL named resource. */
  private static final String DFS_SHARE_ACL = "dfsShareAcl";

  /** Fragement used for creating the share ACL named resource. */
  private static final String SHARE_ACL = "shareAcl";

  /** The config option that forces us to ignore the share ACL. */
  private static final String CONFIG_SKIP_SHARE_ACL = 
      "filesystemadaptor.skipShareAccessControl";

  /** The config parameter name for the prefix for BUILTIN groups. */
  private static final String CONFIG_BUILTIN_PREFIX =
      "filesystemadaptor.builtinGroupPrefix";

  /** The config parameter name for the adaptor namespace. */
  private static final String CONFIG_NAMESPACE = "adaptor.namespace";

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private static final ThreadLocal<SimpleDateFormat> dateFormatter =
      new ThreadLocal<SimpleDateFormat>() {
          @Override
          protected SimpleDateFormat initialValue() {
              return new SimpleDateFormat("yyyy-MM-dd");
          }
      };

  /**
   * The set of Windows accounts that qualify for inclusion in an Acl
   * regardless of the value returned by {@link #isBuiltin(String)}.
   */
  private Set<String> supportedWindowsAccounts;

  /**
   * The prefix used to determine if an account is a built-in account.
   * If an account starts with this string then it is considered a built-in
   * account.
   */
  private String builtinPrefix;

  /** The namespace applied to ACL Principals. */
  private String namespace;

  /** If true, crawl hidden files and folders.  Default is false. */
  private boolean crawlHiddenFiles;

  private AdaptorContext context;
  private Path rootPath;
  private DocId rootPathDocId;
  private FileDelegate delegate;
  private boolean skipShareAcl;
  private boolean monitorForUpdates;

  /** Filter that may exclude files whose last modified time is too old. */
  private FileTimeFilter lastModifiedTimeFilter;
  private FileTimeFilter lastAccessTimeFilter;

  public FsAdaptor() {
    // At the moment, we only support Windows.
    if (System.getProperty("os.name").startsWith("Windows")) {
      delegate = new WindowsFileDelegate();
    } else {
      throw new IllegalStateException(
          "Windows is the only supported platform.");
    }
  }

  @VisibleForTesting
  FsAdaptor(FileDelegate delegate) {
    this.delegate = delegate;
  }

  @VisibleForTesting
  Set<String> getSupportedWindowsAccounts() {
    return supportedWindowsAccounts;
  }

  @VisibleForTesting
  String getBuiltinPrefix() {
    return builtinPrefix;
  }

  @VisibleForTesting
  String getNamespace() {
    return namespace;
  }

  @Override
  public void initConfig(Config config) {
    config.addKey(CONFIG_SRC, null);
    config.addKey(CONFIG_SUPPORTED_ACCOUNTS,
        "BUILTIN\\Administrators,Everyone,BUILTIN\\Users,BUILTIN\\Guest,"
        + "NT AUTHORITY\\INTERACTIVE,NT AUTHORITY\\Authenticated Users");
    config.addKey(CONFIG_BUILTIN_PREFIX, "BUILTIN\\");
    config.addKey(CONFIG_NAMESPACE, Principal.DEFAULT_NAMESPACE);
    config.addKey(CONFIG_SKIP_SHARE_ACL, "false");
    config.addKey(CONFIG_CRAWL_HIDDEN_FILES, "false");
    config.addKey(CONFIG_LAST_ACCESSED_DAYS, "");
    config.addKey(CONFIG_LAST_ACCESSED_DATE, "");
    config.addKey(CONFIG_LAST_MODIFIED_DAYS, "");
    config.addKey(CONFIG_LAST_MODIFIED_DATE, "");
    config.addKey("filesystemadaptor.monitorForUpdates", "true");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    this.context = context;
    String source = context.getConfig().getValue(CONFIG_SRC);
    if (source.isEmpty()) {
      throw new InvalidConfigurationException("The configuration value "
          + CONFIG_SRC + " is empty. Please specify a valid root path.");
    }
    rootPath = delegate.getPath(source);
    log.log(Level.CONFIG, "rootPath: {0}", rootPath);

    builtinPrefix = context.getConfig().getValue(CONFIG_BUILTIN_PREFIX);
    log.log(Level.CONFIG, "builtinPrefix: {0}", builtinPrefix);

    namespace = context.getConfig().getValue(CONFIG_NAMESPACE);
    log.log(Level.CONFIG, "namespace: {0}", namespace);

    String accountsStr =
        context.getConfig().getValue(CONFIG_SUPPORTED_ACCOUNTS);
    supportedWindowsAccounts = Collections.unmodifiableSet(Sets.newHashSet(
        Splitter.on(',').trimResults().split(accountsStr)));
    log.log(Level.CONFIG, "supportedWindowsAccounts: {0}",
        supportedWindowsAccounts);

    crawlHiddenFiles = Boolean.parseBoolean(
        context.getConfig().getValue(CONFIG_CRAWL_HIDDEN_FILES));
    log.log(Level.CONFIG, "crawlHiddenFiles: {0}",
        crawlHiddenFiles);
    if (!crawlHiddenFiles && delegate.isHidden(rootPath)) {
      throw new InvalidConfigurationException("The path " + rootPath + " is "
          + "hidden. To crawl hidden content, you must set the configuration "
          + "property \"filesystemadaptor.crawlHiddenFiles\" to \"true\".");
    }

    // The Administrator may bypass Share access control.
    skipShareAcl = Boolean.parseBoolean(
        context.getConfig().getValue(CONFIG_SKIP_SHARE_ACL));
    log.log(Level.CONFIG, "skipShareAcl: {0}", skipShareAcl);

    // Add filters that may exclude older content.
    lastAccessTimeFilter = getFileTimeFilter(context.getConfig(),
        CONFIG_LAST_ACCESSED_DAYS, CONFIG_LAST_ACCESSED_DATE);
    lastModifiedTimeFilter = getFileTimeFilter(context.getConfig(),
        CONFIG_LAST_MODIFIED_DAYS, CONFIG_LAST_MODIFIED_DATE);

    monitorForUpdates = Boolean.parseBoolean(
        context.getConfig().getValue("filesystemadaptor.monitorForUpdates"));
    log.log(Level.CONFIG, "monitorForUpdates: {0}", monitorForUpdates);

    try {
      rootPathDocId = delegate.newDocId(rootPath);
    } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException("The path " + rootPath
             + " is not valid path - " + e.getMessage() + ".");
    }

    // TODO(mifern): Using a path of \\host\ns\link\FolderA will be
    // considered non-DFS even though \\host\ns\link is a DFS link path.
    // This is OK for now since it will fail all three checks below and
    // will throw an InvalidConfigurationException.
    if (delegate.isDfsLink(rootPath)) {
      Path dfsActiveStorage = delegate.resolveDfsLink(rootPath);
      log.log(Level.INFO, "Using a DFS path resolved to {0}", dfsActiveStorage);
      validateShare(rootPath);
    } else if (delegate.isDfsNamespace(rootPath)) {
      log.log(Level.INFO, "Using a DFS namespace." );
      for (Path link : delegate.enumerateDfsLinks(rootPath)) {
        // Postpone full validation until crawl time.
        try {
          Path dfsActiveStorage = delegate.resolveDfsLink(link);
          log.log(Level.INFO, "DFS path {0} resolved to {1}",
                  new Object[] {link, dfsActiveStorage});
        } catch (IOException e) {
          log.log(Level.WARNING, "Unable to resolve DFS link", e);
        }
      }
    } else if (rootPath.equals(rootPath.getRoot())) {
      log.log(Level.INFO, "Using a non-DFS path.");
      validateShare(rootPath);
    } else {
      // We currently only support a config path that is a root.
      // Non-root paths will fail to produce Acls for all the folders up
      // to the root from the configured path, so we limit configuration
      // only to root paths.
      throw new InvalidConfigurationException(
          "Invalid " + CONFIG_SRC + " . Acceptable paths need to be"
          + " either \\\\host\\namespace or \\\\host\\namespace\\link"
          + " or \\\\host\\share.");
    }
  }

  @Override
  public void destroy() {
    delegate.destroy();
  }

  /** Verify the path is available and we have access to it. */
  private void validateShare(Path sharePath) throws IOException {
    if (delegate.isDfsNamespace(sharePath)) {
      throw new AssertionError("validateShare can only be called "
          + "on DFS links or active storage paths");
    }

    if (!delegate.isDirectory(sharePath)) {
      throw new IOException("The path " + sharePath + " is not accessible. "
          + "The path does not exist, or it is not a directory, or it is not "
          + "shared, or its hosting file server is currently unavailable.");
    }

    // Verify that the adaptor has permission to read the contents of the root.
    try {
      delegate.newDirectoryStream(sharePath).close();
    } catch (AccessDeniedException e) {
      throw new IOException("Unable to list the contents of " + sharePath
          + ". This can happen if the Windows account used to crawl "
          + "the path does not have sufficient permissions.", e);
    }

    // Verify that the adaptor has permission to read the Acl and share Acl.
    try {
      readShareAcls(sharePath);
      delegate.getAclViews(sharePath);
    } catch (IOException e) {
      throw new IOException("Unable to read ACLs for " + sharePath
          + ". This can happen if the Windows account used to crawl "
          + "the path does not have sufficient permissions. A Windows "
          + "account with sufficient permissions to read content, "
          + "attributes and ACLs is required to crawl a path.", e);
    }
  }

  private FileTimeFilter getFileTimeFilter(Config config, String configDaysKey,
       String configDateKey) throws StartupException {
    String configDays = config.getValue(configDaysKey);
    String configDate = config.getValue(configDateKey);
    if (!configDays.isEmpty() && !configDate.isEmpty()) {
      throw new InvalidConfigurationException("Please specify only one of "
          + configDaysKey + " or " + configDateKey + ".");
    } else if (!configDays.isEmpty()) {
      log.log(Level.CONFIG, configDaysKey + ": " + configDays);
      try {
        return new ExpiringFileTimeFilter(Integer.parseInt(configDays));
      } catch (NumberFormatException e) {
        throw new InvalidConfigurationException(configDaysKey
            + " must be specified as a positive integer number of days.", e);
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException(configDaysKey
            + " must be specified as a positive integer number of days.", e);
      }
    } else if (!configDate.isEmpty()) {
      log.log(Level.CONFIG, configDateKey + ": " + configDate);
      SimpleDateFormat iso8601DateFormat = new SimpleDateFormat("yyyy-MM-dd");
      iso8601DateFormat.setCalendar(Calendar.getInstance());
      iso8601DateFormat.setLenient(true);
      try {
        return new AbsoluteFileTimeFilter(FileTime.fromMillis(
            iso8601DateFormat.parse(configDate).getTime()));
      } catch (ParseException e) {
        throw new InvalidConfigurationException(configDateKey
            + " must be specified in the format \"YYYY-MM-DD\".", e);
      } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException(configDateKey
            + " must be a date in the past.", e);
      }
    } else {
      return new AlwaysAllowFileTimeFilter();
    }
  }

  private ShareAcls readShareAcls(Path share) throws IOException {
    Acl shareAcl;
    Acl dfsShareAcl;

    if (skipShareAcl) {
      // Ignore the Share ACL, but create a benign placeholder.
      dfsShareAcl = null;
      shareAcl = new Acl.Builder().setEverythingCaseInsensitive()
          .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
    } else if (delegate.isDfsNamespace(share)) {
      throw new AssertionError("readShareAcls can only be called "
          + "on DFS links or active storage paths");
    } else if (delegate.isDfsLink(share)) {
      // For a DFS UNC we have a DFS Acl that must be sent. Also, the share Acl
      // must be the Acl for the target storage UNC.
      AclBuilder builder = new AclBuilder(share,
          delegate.getDfsShareAclView(share),
          supportedWindowsAccounts, builtinPrefix, namespace);
      dfsShareAcl = builder.getAcl().setInheritanceType(
          InheritanceType.AND_BOTH_PERMIT).build();

      // Push the Acl for the active storage UNC path.
      Path activeStorage = delegate.resolveDfsLink(share);
      if (activeStorage == null) {
        throw new IOException("The DFS path " + share
            + " does not have an active storage.");
      }

      builder = new AclBuilder(activeStorage,
          delegate.getShareAclView(activeStorage),
          supportedWindowsAccounts, builtinPrefix, namespace);
      shareAcl = builder.getAcl()
          .setInheritFrom(delegate.newDocId(share), DFS_SHARE_ACL)
          .setInheritanceType(InheritanceType.AND_BOTH_PERMIT).build();
    } else {
      // For a non-DFS UNC we have only have a share Acl to push.
      AclBuilder builder = new AclBuilder(share,
          delegate.getShareAclView(share),
          supportedWindowsAccounts, builtinPrefix, namespace);
      dfsShareAcl = null;
      shareAcl = builder.getAcl().setInheritanceType(
          InheritanceType.AND_BOTH_PERMIT).build();
    }

    return new ShareAcls(shareAcl, dfsShareAcl);
  }

  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException,
      IOException {
    log.entering("FsAdaptor", "getDocIds", new Object[] {pusher, rootPath});
    pusher.pushDocIds(Arrays.asList(delegate.newDocId(rootPath)));
    log.exiting("FsAdaptor", "getDocIds", pusher);
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    log.entering("FsAdaptor", "getDocContent",
        new Object[] {req, resp});
    DocId id = req.getDocId();
    Path doc;

    try {
      doc = delegate.getPath(id.getUniqueId());
    } catch (InvalidPathException e) {
      log.log(Level.WARNING,
          "The docid {0} is not a valid id generated by the adaptor.", id);
      resp.respondNotFound();
      return;
    }

    DocId docid;
    try {
      docid = delegate.newDocId(doc);
    } catch (IllegalArgumentException e) {
      log.log(Level.WARNING, "The docid {0} is not a valid id - {1}.",
              new Object[] { doc, e.getMessage() });
      resp.respondNotFound();
      return;
    }
    if (!id.equals(docid)) {
      log.log(Level.WARNING,
          "The docid {0} is not a valid id generated by the adaptor.", id);
      resp.respondNotFound();
      return;
    }

    if (!isVisibleDescendantOfRoot(doc)) {
      resp.respondNotFound();
      return;
    }

    BasicFileAttributes attrs;
    try {
      attrs = delegate.readBasicAttributes(doc);
    } catch (FileNotFoundException e) {
      log.log(Level.INFO, "Not found: {0}", doc);
      resp.respondNotFound();
      return;
    } catch (NoSuchFileException e) {
      log.log(Level.INFO, "Not found: {0}", doc);
      resp.respondNotFound();
      return;
    }      

    if (!isFileOrFolder(doc)) {
      log.log(Level.INFO, "The path {0} is not a regular file or directory.",
              doc);
      resp.respondNotFound();
      return;
    }

    final boolean docIsDirectory = attrs.isDirectory();
    final FileTime lastAccessTime = attrs.lastAccessTime();

    if (!docIsDirectory) {
      if (lastAccessTimeFilter.excluded(lastAccessTime)) {
        log.log(Level.FINE, "Skipping {0} because it was last accessed {1}.",
            new Object[] {doc, lastAccessTime.toString().substring(0, 10)});
        resp.respondNotFound();
        return;
      }
      if (lastModifiedTimeFilter.excluded(attrs.lastModifiedTime())) {
        log.log(Level.FINE, "Skipping {0} because it was last modified {1}.",
            new Object[] {doc, 
                attrs.lastModifiedTime().toString().substring(0, 10)});
        resp.respondNotFound();
        return;
      }
    }

    resp.setDisplayUrl(doc.toUri());
    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("Creation Time", dateFormatter.get().format(
        new Date(attrs.creationTime().toMillis())));

    // TODO(mifern): Include extended attributes.

    if (delegate.isDfsNamespace(doc)) {
      // Enumerate links in a namespace.
      getDfsNamespaceContent(doc, id, resp);
    } else {
      // If we are at the root of a filesystem or share point, supply the
      // SHARE ACL. If it is a DFS Link, also include the DFS SHARE ACL.
      if (doc.equals(rootPath) || delegate.isDfsLink(doc)) {
        // TODO(bmj): Maybe have validateShare return the share ACLs it read.
        validateShare(doc);
        ShareAcls shareAcls = readShareAcls(doc);
        if (shareAcls.dfsShareAcl != null) {
          resp.putNamedResource(DFS_SHARE_ACL, shareAcls.dfsShareAcl);
        }
        resp.putNamedResource(SHARE_ACL, shareAcls.shareAcl);

        if (monitorForUpdates) {
          delegate.startMonitorPath(doc, context.getAsyncDocIdPusher());
        }
      }

      // Populate the document filesystem ACL.
      getFileAcls(doc, resp);

      // Populate the document content.
      if (docIsDirectory) {
        getDirectoryContent(doc, id, resp);
      } else {
        getFileContent(doc, lastAccessTime, resp);
      }
    }
    log.exiting("FsAdaptor", "getDocContent");
  }

  /* Returns the parent of a Path, or its root if it has no parent. */
  private Path getParent(Path path) throws IOException {
    Path parent = path.getParent();
    return (parent == null) ? path.getRoot() : parent;
  }

  /* Populate the document ACL in the response. */
  private void getFileAcls(Path doc, Response resp) throws IOException {
    final boolean isRoot = doc.equals(rootPath) || delegate.isDfsLink(doc);
    final boolean isDirectory = delegate.isDirectory(doc);
    AclFileAttributeViews aclViews = delegate.getAclViews(doc);
    boolean hasNoInheritedAcl =
        aclViews.getInheritedAclView().getAcl().isEmpty();

    Path inheritFrom;
    if (isRoot) {
      // Roots will inherit from their own share ACLs.
      inheritFrom = doc;
    } else if (hasNoInheritedAcl) {
      // Files and folders that do not inherit permissions from their parent
      // inherit directly from the share ACL.
      for (inheritFrom = doc;
           !(inheritFrom.equals(rootPath) || delegate.isDfsLink(inheritFrom));
           inheritFrom = inheritFrom.getParent());
    } else {
      // All others inherit permissions from their parent.
      inheritFrom = getParent(doc);
    }
    if (inheritFrom == null) {
      throw new IOException("Unable to determine inherited ACL for " + doc);
    }
    DocId inheritFromDocId = delegate.newDocId(inheritFrom);

    AclBuilder builder;
    Acl acl;
    if (isRoot || hasNoInheritedAcl) {
      builder = new AclBuilder(doc, aclViews.getCombinedAclView(),
          supportedWindowsAccounts, builtinPrefix, namespace);
      acl = builder.getAcl().setInheritFrom(inheritFromDocId, SHARE_ACL)
          .setInheritanceType(isDirectory ? InheritanceType.CHILD_OVERRIDES
                              : InheritanceType.LEAF_NODE).build();
    } else {
      builder = new AclBuilder(doc, aclViews.getDirectAclView(),
          supportedWindowsAccounts, builtinPrefix, namespace);
      if (isDirectory) {
        acl = builder.getAcl()
            .setInheritFrom(inheritFromDocId, CHILD_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
      } else {
        acl = builder.getAcl()
            .setInheritFrom(inheritFromDocId, CHILD_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.LEAF_NODE).build();
      }
    }
    log.log(Level.FINEST, "Setting Acl: doc: {0}, acl: {1}",
        new Object[] { doc, acl });
    resp.setAcl(acl);

    // Add the additional Acls for a folder.
    if (isDirectory) {
      if (isRoot || hasNoInheritedAcl) {
        resp.putNamedResource(ALL_FOLDER_INHERIT_ACL, 
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(inheritFromDocId, SHARE_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
      } else {
        resp.putNamedResource(ALL_FOLDER_INHERIT_ACL, 
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(inheritFromDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(inheritFromDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(inheritFromDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(inheritFromDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
      }
    }
  }

  /* Makes HTML document with web links to namespace's DFS links. */
  private void getDfsNamespaceContent(Path doc, DocId docid, Response resp)
      throws IOException {
    HtmlResponseWriter writer = createHtmlResponseWriter(resp);
    writer.start(docid, getFileName(doc));
    for (Path link : delegate.enumerateDfsLinks(doc)) {
      DocId docId;
      try {
        docId = delegate.newDocId(link);
      } catch (IllegalArgumentException e) {
        log.log(Level.WARNING, "Skipping {0} because {1}.",
                new Object[] { doc, e.getMessage() });
        continue;
      }
      writer.addLink(docId, getFileName(link));
    }
    writer.finish();
  }

  /* Makes HTML document with links this directory's files and folder. */
  private void getDirectoryContent(Path doc, DocId docid, Response resp)
      throws IOException {
    HtmlResponseWriter writer = createHtmlResponseWriter(resp);
    writer.start(docid, getFileName(doc));
    DirectoryStream<Path> files = delegate.newDirectoryStream(doc);
    try {
      for (Path file : files) {
        if (isFileOrFolder(file)) {
          DocId docId;
          try {
            docId = delegate.newDocId(file);
          } catch (IllegalArgumentException e) {
            log.log(Level.WARNING, "Skipping {0} because {1}.",
                    new Object[] { doc, e.getMessage() });
            continue;
          }
          writer.addLink(docId, getFileName(file));
        }
      }
    } finally {
      files.close();
    }
    writer.finish();
  }

  /* Adds the file's content to the response. */
  private void getFileContent(Path doc, FileTime lastAccessTime, Response resp)
      throws IOException {
    resp.setContentType(delegate.probeContentType(doc));
    InputStream input = delegate.newInputStream(doc);
    try {
      IOHelper.copyStream(input, resp.getOutputStream());
    } finally {
      try {
        input.close();
      } finally {
        try {
          delegate.setLastAccessTime(doc, lastAccessTime);
        } catch (IOException e) {
          // This failure can be expected. We can have full permissions
          // to read but not write/update permissions.
          log.log(Level.CONFIG,
                  "Unable to restore last access time for {0}.", doc);
        }
      }
    }
  }

  private HtmlResponseWriter createHtmlResponseWriter(Response response)
      throws IOException {
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, context.getDocIdEncoder(),
        Locale.ENGLISH);
  }

  @VisibleForTesting
  String getFileName(Path file) {
    // NOTE: file.getFileName() fails for UNC paths. Use file.toFile() instead.
    String name = file.toFile().getName();
    return name.isEmpty() ? file.getRoot().toString() : name;
  }

  /**
   * Returns true if the path is a regular file or a folder;
   * false if the path is a link, a special file, or doesn't exist.
   */
  @VisibleForTesting
  boolean isFileOrFolder(Path p) throws IOException {
    return delegate.isRegularFile(p) || delegate.isDirectory(p);
  }

  /**
   * Verifies that the file is a descendant of the root directory,
   * and that it, nor none of its ancestors, is hidden.
   */
  @VisibleForTesting
  boolean isVisibleDescendantOfRoot(Path doc) throws IOException {
    for (Path file = doc; file != null; file = getParent(file)) {
      if (!crawlHiddenFiles && delegate.isHidden(file)) {
        if (doc.equals(file)) {
          log.log(Level.WARNING, "Skipping {0} because it is hidden.", doc);
        } else {
          log.log(Level.WARNING,
              "Skipping {0} because it is hidden under {1}.",
              new Object[] { doc, file });
        }
        return false;
      }
      if (file.equals(rootPath)) {
        return true;
      }
    }
    log.log(Level.WARNING,
        "Skipping {0} because it is not a descendant of {1}.",
        new Object[] { doc, rootPath });
    return false;
  }

  private class ShareAcls {
    private final Acl shareAcl;
    private final Acl dfsShareAcl;

    public ShareAcls(Acl shareAcl, Acl dfsShareAcl) {
      Preconditions.checkNotNull(shareAcl, "the share Acl may not be null");
      this.shareAcl = shareAcl;
      this.dfsShareAcl = dfsShareAcl;
    }
  }

  private static interface FileTimeFilter {
    public boolean excluded(FileTime fileTime);
  }

  private static class AlwaysAllowFileTimeFilter implements FileTimeFilter {
    @Override
    public boolean excluded(FileTime fileTime) {
      return false;
    }
  }

  private static class AbsoluteFileTimeFilter implements FileTimeFilter {
    private final FileTime oldestAllowed;

    public AbsoluteFileTimeFilter(FileTime oldestAllowed) {
      Preconditions.checkArgument(oldestAllowed.compareTo(
          FileTime.fromMillis(System.currentTimeMillis())) < 0,
          oldestAllowed.toString().substring(0, 10)
          + " is in the future.");
      this.oldestAllowed = oldestAllowed;
    }

    @Override
    public boolean excluded(FileTime fileTime) {
      return fileTime.compareTo(oldestAllowed) < 0;
    }
  }

  private static class ExpiringFileTimeFilter implements FileTimeFilter {
    private static final long MILLIS_PER_DAY = 24 * 60 * 60 * 1000L;
    private final long relativeMillis;

    public ExpiringFileTimeFilter(int daysOld) {
      Preconditions.checkArgument(daysOld > 0, "The number of days old for "
          + "expired content must be greater than zero.");
      this.relativeMillis = daysOld * MILLIS_PER_DAY;
    }

    @Override
    public boolean excluded(FileTime fileTime) {
      FileTime oldestAllowed =
          FileTime.fromMillis(System.currentTimeMillis() - relativeMillis);
      return fileTime.compareTo(oldestAllowed) < 0;
    }
  }

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new FsAdaptor(), args);
  }
}
