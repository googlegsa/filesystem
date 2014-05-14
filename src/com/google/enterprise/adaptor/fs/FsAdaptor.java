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
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.UnsupportedPlatformException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.AccessDeniedException;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
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
 * <li>Supports UNC path to single matchine's share
 * <li>Supports UNC path to standalone DFS
 * <li>Supports UNC path to domain DFS
 * <li>Uses hierarchical ACL model
 * </ul>
 */
public class FsAdaptor extends AbstractAdaptor implements
    PollingIncrementalLister {
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

  private static final String ALL_FOLDER_INHERIT_ACL = "allFoldersAcl";
  private static final String ALL_FILE_INHERIT_ACL = "allFilesAcl";
  private static final String CHILD_FOLDER_INHERIT_ACL = "childFoldersAcl";
  private static final String CHILD_FILE_INHERIT_ACL = "childFilesAcl";

  /** DocId for the DFS share ACL named resource. */
  private static final DocId DFS_SHARE_ACL_DOCID = new DocId("dfsShareAcl");

  /** DocId for the share ACL named resource. */
  private static final DocId SHARE_ACL_DOCID = new DocId("shareAcl");

  /** The config parameter name for the prefix for BUILTIN groups. */
  private static final String CONFIG_BUILTIN_PREFIX =
      "filesystemadaptor.builtinGroupPrefix";

  /** The config parameter name for the max incremental batch latency. */
  private static final String CONFIG_MAX_INCREMENTAL_LATENCY =
      "adaptor.incrementalPollPeriodSecs";

  /** The config parameter name for the adaptor namespace. */
  private static final String CONFIG_NAMESPACE = "adaptor.namespace";

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private static final ThreadLocal<SimpleDateFormat> dateFormatter =
      new ThreadLocal<SimpleDateFormat>() {
          @Override
          protected SimpleDateFormat initialValue()
          {
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
  private boolean isDfsUnc;
  private DocId rootPathDocId;
  private FileDelegate delegate;
  private ShareAcls lastPushedShareAcls = null;

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
    config.addKey(CONFIG_SRC, "");
    config.addKey(CONFIG_SUPPORTED_ACCOUNTS,
        "BUILTIN\\Administrators,Everyone,BUILTIN\\Users,BUILTIN\\Guest,"
        + "NT AUTHORITY\\INTERACTIVE,NT AUTHORITY\\Authenticated Users");
    config.addKey(CONFIG_BUILTIN_PREFIX, "BUILTIN\\");
    config.addKey(CONFIG_NAMESPACE, Principal.DEFAULT_NAMESPACE);
    config.addKey(CONFIG_CRAWL_HIDDEN_FILES, "false");
    config.overrideKey(CONFIG_MAX_INCREMENTAL_LATENCY, "300");
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

    // TODO(mifern): Using a path of \\host\ns\link\FolderA will be
    // considered non-DFS even though \\host\ns\link is a DFS link path.
    // This is OK for now since the check for root path below will cause an
    // InvalidConfigurationException.
    Path dfsActiveStorage = delegate.getDfsUncActiveStorageUnc(rootPath);
    isDfsUnc = (dfsActiveStorage != null);
    log.log(Level.INFO, "Using a {0} path.", isDfsUnc ? "DFS" : "non-DFS");

    if (isDfsUnc) {
      // We assume that DFS link has an active storage path that is
      // different from the actual DFS link path.
      final boolean isDfsLink = !rootPath.equals(dfsActiveStorage);
      if (!isDfsLink) {
        throw new InvalidConfigurationException("The DFS path " + rootPath +
            " is not a supported DFS path. Only DFS links of the format " +
            "\\\\host\\namespace\\link are supported.");
      }
    } else {
      if (!rootPath.equals(rootPath.getRoot())) {
        // We currently only support a config path that is a root.
        // Non-root paths will fail to produce Acls for all the folders up
        // to the root from the configured path, so we limit configuration
        // only to root paths.
        throw new InvalidConfigurationException(
            "Only root paths are supported. Use a path such as C:\\ or " +
            "X:\\ or \\\\host\\share. Additionally, you can specify a " +
            "DFS link path of the form \\\\host\\ns\\link.");
      }
    }
    if (!delegate.isDirectory(rootPath)) {
      throw new IOException("The path " + rootPath + " is not accessible. "
          + "The path does not exist, or it is not a directory, or it is not "
          + "shared, or its hosting file server is currently unavailable.");
    }

    // Verify that the adaptor has permission to read the contents of the root.
    try {
      delegate.newDirectoryStream(rootPath);
    } catch (AccessDeniedException e) {
      throw new IOException("Unable to list the contents of " + rootPath +
          ". This can happen if the Windows account used to crawl " +
          "the path does not have sufficient permissions.", e);
    }

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

    // Verify that the adaptor has permission to read the Acl and share Acl.
    try {
      readShareAcls();
      delegate.getAclViews(rootPath);
    } catch (IOException e) {
      throw new IOException("Unable to read ACLs for " + rootPath +
          ". This can happen if the Windows account used to crawl " +
          "the path does not have sufficient permissions. A Windows " +
          "account with sufficient permissions to read content, " +
          "attributes and ACLs is required to crawl a path.", e);
    }

    rootPathDocId = delegate.newDocId(rootPath);
    delegate.startMonitorPath(rootPath, context.getAsyncDocIdPusher());
    context.setPollingIncrementalLister(this);
  }

  @Override
  public void destroy() {
    delegate.destroy();
  }

  private ShareAcls readShareAcls() throws IOException {
    Acl shareAcl;
    Acl dfsShareAcl;

    if (isDfsUnc) {
      // For a DFS UNC we have a DFS Acl that must be sent. Also, the share Acl
      // must be the Acl for the target storage UNC.
      // TODO(mifern): This assumes that rootPath is a DFS link since it calls
      // getParent determine the DFS namespace UNC path.
      AclBuilder builder = new AclBuilder(rootPath,
          delegate.getDfsShareAclView(rootPath.getParent()),
          supportedWindowsAccounts, builtinPrefix, namespace);
      dfsShareAcl = builder.getAcl().setInheritanceType(
          InheritanceType.AND_BOTH_PERMIT).build();

      // Push the Acl for the active storage UNC path.
      Path activeStorage = delegate.getDfsUncActiveStorageUnc(rootPath);
      if (activeStorage == null) {
        throw new IOException("The DFS path " + rootPath +
            " does not have an active storage.");
      }

      builder = new AclBuilder(activeStorage,
          delegate.getShareAclView(activeStorage),
          supportedWindowsAccounts, builtinPrefix, namespace);
      shareAcl = builder.getAcl()
          .setInheritFrom(DFS_SHARE_ACL_DOCID)
          .setInheritanceType(InheritanceType.AND_BOTH_PERMIT).build();
    } else {
      // For a non-DFS UNC we have only have a share Acl to push.
      AclBuilder builder = new AclBuilder(rootPath,
          delegate.getShareAclView(rootPath),
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
    pushShareAcls(pusher, true);
    log.exiting("FsAdaptor", "getDocIds", pusher);
  }

  @Override
  public void getModifiedDocIds(DocIdPusher pusher)
      throws InterruptedException, IOException {
    log.entering("FsAdaptor", "getModifiedDocIds");
    pushShareAcls(pusher, false);
    log.exiting("FsAdaptor", "getModifiedDocIds", pusher);
  }

  private synchronized void pushShareAcls(DocIdPusher pusher,
      boolean forcePush) throws InterruptedException, IOException {
    // The share Acls may not have been pushed yet. So if lastPushedShareAcls
    // is null, we want to force a push if there are any share Acls.
    forcePush = forcePush || (lastPushedShareAcls == null);

    // The pusher does not support fragments in named resources.
    // Feed a DocId that is just the SHARE_ACL fragment to avoid
    // collisions with the root docid.
    ShareAcls shareAcls = readShareAcls();
    Map<DocId, Acl> namedResources = new HashMap<DocId, Acl>();
    if ((shareAcls.dfsShareAcl != null) && (forcePush ||
        !shareAcls.dfsShareAcl.equals(lastPushedShareAcls.dfsShareAcl))) {
      namedResources.put(DFS_SHARE_ACL_DOCID, shareAcls.dfsShareAcl);
    }
    if ((shareAcls.shareAcl != null) && (forcePush ||
        !shareAcls.shareAcl.equals(lastPushedShareAcls.shareAcl))) {
      namedResources.put(SHARE_ACL_DOCID, shareAcls.shareAcl);
    }
    if (namedResources.size() > 0) {
      pusher.pushNamedResources(namedResources);
      lastPushedShareAcls = shareAcls;
    }
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    log.entering("FsAdaptor", "getDocContent",
        new Object[] {req, resp});
    DocId id = req.getDocId();
    Path doc = delegate.getPath(id.getUniqueId());

    if (!isSupportedPath(doc)) {
      log.log(Level.WARNING, "The path {0} is not a supported file type.", doc);
      resp.respondNotFound();
      return;
    }

    final boolean docIsDirectory = delegate.isDirectory(doc);

    if (!id.equals(delegate.newDocId(doc))) {
      log.log(Level.WARNING,
          "The {0} is not a valid id generated by the adaptor.", id);
      resp.respondNotFound();
      return;
    }

    if (!isVisibleDescendantOfRoot(doc)) {
      resp.respondNotFound();
      return;
    }

    // Populate the document metadata.
    BasicFileAttributes attrs = delegate.readBasicAttributes(doc);
    final FileTime lastAccessTime = attrs.lastAccessTime();

    resp.setDisplayUrl(doc.toUri());
    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("Creation Time", dateFormatter.get().format(
        new Date(attrs.creationTime().toMillis())));
    if (!docIsDirectory) {
      resp.setContentType(delegate.probeContentType(doc));
    }

    // TODO(mifern): Include extended attributes.

    // Populate the document ACL.
    final boolean isRoot = id.equals(rootPathDocId);
    DocId parentDocId = null;
    if (!isRoot) {
      final Path parent = doc.getParent();
      if (parent == null) {
        throw new IOException("Unable to get the parent of " + doc);
      }
      parentDocId = delegate.newDocId(parent);
    }

    AclFileAttributeViews aclViews = delegate.getAclViews(doc);
    boolean hasNoInheritedAcl =
        aclViews.getInheritedAclView().getAcl().isEmpty();
    AclBuilder builder;
    Acl acl;
    if (isRoot || hasNoInheritedAcl) {
      builder = new AclBuilder(doc, aclViews.getCombinedAclView(),
          supportedWindowsAccounts, builtinPrefix, namespace);
      acl = builder.getAcl().setInheritFrom(SHARE_ACL_DOCID)
          .setInheritanceType(docIsDirectory ? InheritanceType.CHILD_OVERRIDES
                              : InheritanceType.LEAF_NODE).build();
    } else {
      builder = new AclBuilder(doc, aclViews.getDirectAclView(),
          supportedWindowsAccounts, builtinPrefix, namespace);
      if (docIsDirectory) {
        acl = builder.getAcl()
            .setInheritFrom(parentDocId, CHILD_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
      } else {
        acl = builder.getAcl()
            .setInheritFrom(parentDocId, CHILD_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.LEAF_NODE).build();
      }
    }
    log.log(Level.FINEST, "Setting Acl: doc: {0}, acl: {1}",
        new Object[] { doc, acl });
    resp.setAcl(acl);

    // Push the additional Acls for a folder.
    if (docIsDirectory) {
      if (isRoot || hasNoInheritedAcl) {
        resp.putNamedResource(ALL_FOLDER_INHERIT_ACL, 
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(SHARE_ACL_DOCID)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(SHARE_ACL_DOCID)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(SHARE_ACL_DOCID)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(SHARE_ACL_DOCID)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
      } else {
        resp.putNamedResource(ALL_FOLDER_INHERIT_ACL, 
            builder.getInheritableByAllDescendentFoldersAcl()
            .setInheritFrom(parentDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(ALL_FILE_INHERIT_ACL,
            builder.getInheritableByAllDescendentFilesAcl()
            .setInheritFrom(parentDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FOLDER_INHERIT_ACL,
            builder.getInheritableByChildFoldersOnlyAcl()
            .setInheritFrom(parentDocId, ALL_FOLDER_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
        resp.putNamedResource(CHILD_FILE_INHERIT_ACL,
            builder.getInheritableByChildFilesOnlyAcl()
            .setInheritFrom(parentDocId, ALL_FILE_INHERIT_ACL)
            .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build());
      }
    }

    // Populate the document content.
    if (docIsDirectory) {
      HtmlResponseWriter writer = createHtmlResponseWriter(resp);
      writer.start(id, getFileName(doc));
      for (Path file : delegate.newDirectoryStream(doc)) {
        if (isSupportedPath(file)) {
          writer.addLink(delegate.newDocId(file), getFileName(file));
        }
      }
      writer.finish();
    } else {
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
    log.exiting("FsAdaptor", "getDocContent");
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

  @VisibleForTesting
  boolean isSupportedPath(Path p) throws IOException {
    return delegate.isRegularFile(p) || delegate.isDirectory(p);
  }

  /**
   * Verifies that the file is a descendant of the root directory,
   * and that it, nor none of its ancestors, is hidden.
   */
  @VisibleForTesting
  boolean isVisibleDescendantOfRoot(Path doc) throws IOException {
    for (Path file = doc; file != null; file = file.getParent()) {
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
      Preconditions.checkArgument(!isDfsUnc || (dfsShareAcl != null),
          "the DFS share Acl may not be null");
      this.shareAcl = shareAcl;
      this.dfsShareAcl = dfsShareAcl;
    }
  }

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new FsAdaptor(), args);
  }
}
