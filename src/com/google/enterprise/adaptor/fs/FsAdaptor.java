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
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.AuthnIdentity;
import com.google.enterprise.adaptor.AuthzAuthority;
import com.google.enterprise.adaptor.AuthzStatus;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.Status;
import com.google.enterprise.adaptor.StatusSource;
import com.google.enterprise.adaptor.UserPrincipal;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
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
 * <li>Supports UNC path to single machine's share, such as \\host\share
 * <li>Supports UNC path to standalone or domain-based DFS namespace,
 *     such as \\dfs-server\namespace or \\domain-dfs-server\namespace and
 *     will follow all the DFS links within that namespace
 * <li>Supports UNC path to standalone or domain-based DFS link, such as
 *     \\dfs-server\namespace\link or \\domain-dfs-server\namespace\link
 * <li>Supports multiple UNC paths to any combination of simple file shares,
 *     DFS namespaces, or DFS links
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

  /** The config parameter name for the start paths. */
  private static final String CONFIG_SRC = "filesystemadaptor.src";

  /**
   * The config parameter defining the delimiter used to separate
   * multiple start paths supplied in CONFIG_SRC. Default is ";".
   */
  private static final String CONFIG_SRC_SEPARATOR =
      "filesystemadaptor.src.separator";

  /** The config parameter name for the supported Windows accounts. */
  private static final String CONFIG_SUPPORTED_ACCOUNTS =
      "filesystemadaptor.supportedAccounts";

  /** The config parameter name for turning on/off hidden file indexing. */
  private static final String CONFIG_CRAWL_HIDDEN_FILES =
      "filesystemadaptor.crawlHiddenFiles";

  /** The config parameter name for turning on/off folder indexing. */
  private static final String CONFIG_INDEX_FOLDERS =
      "filesystemadaptor.indexFolders";

  /** The config parameter for strategy of preserving last access time. */
  private static final String CONFIG_PRESERVE_LAST_ACCESS_TIME =
      "filesystemadaptor.preserveLastAccessTime";

  /** The config parameter for the size of the isVisible directory cache. */
  private static final String CONFIG_DIRECTORY_CACHE_SIZE =
      "filesystemadaptor.directoryCacheSize";

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

  /** Enable/disable filesystem change monitors. */
  private static final String CONFIG_MONITOR_UPDATES =
      "filesystemadaptor.monitorForUpdates";

  /** The config option that forces us to ignore the share ACL. */
  private static final String CONFIG_SKIP_SHARE_ACL = 
      "filesystemadaptor.skipShareAccessControl";

  /** The config parameter name for the prefix for BUILTIN groups. */
  private static final String CONFIG_BUILTIN_PREFIX =
      "filesystemadaptor.builtinGroupPrefix";

  /** The config parameter for the Dashboard Status update interval. */
  private static final String CONFIG_STATUS_UPDATE_INTERVAL_MINS =
      "filesystemadaptor.statusUpdateIntervalMinutes";

  /** The config parameter name for the adaptor namespace. */
  private static final String CONFIG_NAMESPACE = "adaptor.namespace";

  /** Config parameter that determins whether search results link to
   *  file system repository or instead to this adaptor. */
  private static final String CONFIG_SEARCH_RESULTS_GO_TO_REPO
       = "filesystemadaptor.searchResultsLinkToRepository";

  /** Fragements used for creating the inherited ACL named resources. */
  private static final String ALL_FOLDER_INHERIT_ACL = "allFoldersAcl";
  private static final String ALL_FILE_INHERIT_ACL = "allFilesAcl";
  private static final String CHILD_FOLDER_INHERIT_ACL = "childFoldersAcl";
  private static final String CHILD_FILE_INHERIT_ACL = "childFilesAcl";

  /** Fragement used for creating the DFS share ACL named resource. */
  private static final String DFS_SHARE_ACL = "dfsShareAcl";

  /** Fragement used for creating the share ACL named resource. */
  private static final String SHARE_ACL = "shareAcl";

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

  /** If true, index the generated documents of links to folder's contents. */
  private boolean indexFolders;

  /** How to enforce preservation of last access time of files and folders. */
  private enum PreserveLastAccessTime { NEVER, IF_ALLOWED, ALWAYS };
  private PreserveLastAccessTime preserveLastAccessTime;

  /** Cache of hidden and visible directories. */
  // TODO(bmj): Cache docIds too, for ACL inheritance purposes.
  private Cache<Path, Hidden> isVisibleCache;

  private AdaptorContext context;
  private FileDelegate delegate;
  private boolean skipShareAcl;
  private boolean monitorForUpdates;

  /** The set of file systems we will be traversing. */
  private Set<Path> startPaths;

  /** The set of file systems currently blocked from traversing. */
  private Set<Path> blockedPaths =
      // TODO(bmj): Use Sets.newConcurrentHashSet() from guava r15.
      Collections.newSetFromMap(new ConcurrentHashMap<Path, Boolean>());

  /** Filter that may exclude files whose last modified time is too old. */
  private FileTimeFilter lastModifiedTimeFilter;
  private FileTimeFilter lastAccessTimeFilter;

  /** Status of file systems we are traversing */
  private Map<Path, FsStatus>fsStatus = new ConcurrentHashMap<Path, FsStatus>();
  private Timer statusUpdateService = new Timer("Dashboard Status Update");
  private long statusUpdateIntervalMillis;

  private boolean resultLinksToShare;
  
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
    // TODO(bmj): Make default separator platform dependent?
    config.addKey(CONFIG_SRC_SEPARATOR, ";");
    config.addKey(CONFIG_SUPPORTED_ACCOUNTS,
        "BUILTIN\\Administrators,Everyone,BUILTIN\\Users,BUILTIN\\Guest,"
        + "NT AUTHORITY\\INTERACTIVE,NT AUTHORITY\\Authenticated Users");
    config.addKey(CONFIG_BUILTIN_PREFIX, "BUILTIN\\");
    config.addKey(CONFIG_NAMESPACE, Principal.DEFAULT_NAMESPACE);
    config.addKey(CONFIG_SKIP_SHARE_ACL, "false");
    config.addKey(CONFIG_CRAWL_HIDDEN_FILES, "false");
    config.addKey(CONFIG_INDEX_FOLDERS, "false");
    config.addKey(CONFIG_PRESERVE_LAST_ACCESS_TIME, 
        PreserveLastAccessTime.ALWAYS.toString());
    config.addKey(CONFIG_DIRECTORY_CACHE_SIZE, "50000");
    config.addKey(CONFIG_LAST_ACCESSED_DAYS, "");
    config.addKey(CONFIG_LAST_ACCESSED_DATE, "");
    config.addKey(CONFIG_LAST_MODIFIED_DAYS, "");
    config.addKey(CONFIG_LAST_MODIFIED_DATE, "");
    config.addKey(CONFIG_MONITOR_UPDATES, "true");
    config.addKey(CONFIG_STATUS_UPDATE_INTERVAL_MINS, "15");
    config.addKey(CONFIG_SEARCH_RESULTS_GO_TO_REPO, "true");
    // Increase the max feed size, which also increases the
    // asyncDocIdSenderQueueSize to 40,000 entries. This would
    // make a full queue about 10MB in size.
    config.overrideKey("feed.maxUrls", "20000");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    this.context = context;
    Config config = context.getConfig();

    String sources = config.getValue(CONFIG_SRC);
    if (sources.isEmpty()) {
      throw new InvalidConfigurationException("The configuration value "
          + CONFIG_SRC + " is empty. Please specify a valid root path.");
    }
    startPaths = getStartPaths(sources, config.getValue(CONFIG_SRC_SEPARATOR));

    builtinPrefix = config.getValue(CONFIG_BUILTIN_PREFIX);
    log.log(Level.CONFIG, "builtinPrefix: {0}", builtinPrefix);

    namespace = config.getValue(CONFIG_NAMESPACE);
    log.log(Level.CONFIG, "namespace: {0}", namespace);

    String accountsStr = config.getValue(CONFIG_SUPPORTED_ACCOUNTS);
    supportedWindowsAccounts = ImmutableSet.copyOf(
        Splitter.on(',').trimResults().omitEmptyStrings().split(accountsStr));
    log.log(Level.CONFIG, "supportedWindowsAccounts: {0}",
        supportedWindowsAccounts);

    crawlHiddenFiles = Boolean.parseBoolean(
        config.getValue(CONFIG_CRAWL_HIDDEN_FILES));
    log.log(Level.CONFIG, "crawlHiddenFiles: {0}", crawlHiddenFiles);

    indexFolders = Boolean.parseBoolean(config.getValue(CONFIG_INDEX_FOLDERS));
    log.log(Level.CONFIG, "indexFolders: {0}", indexFolders);

    resultLinksToShare = Boolean.parseBoolean(
        config.getValue(CONFIG_SEARCH_RESULTS_GO_TO_REPO));
    log.log(Level.CONFIG, "searchResultsLinkToRepository: {0}",
        resultLinksToShare);
    if (!resultLinksToShare) {
      context.setAuthzAuthority(new AccessChecker());
    }

    try {
      preserveLastAccessTime = Enum.valueOf(PreserveLastAccessTime.class,
          config.getValue(CONFIG_PRESERVE_LAST_ACCESS_TIME).toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new InvalidConfigurationException("The value of "
          + CONFIG_PRESERVE_LAST_ACCESS_TIME + " must be one of "
          + EnumSet.allOf(PreserveLastAccessTime.class) + ".", e);
    }
    log.log(Level.CONFIG, "preserveLastAccessTime: {0}",
        preserveLastAccessTime);

    int directoryCacheSize =
        Integer.parseInt(config.getValue(CONFIG_DIRECTORY_CACHE_SIZE));
    log.log(Level.CONFIG, "directoryCacheSize: {0}", directoryCacheSize);
    isVisibleCache = CacheBuilder.newBuilder()
        .initialCapacity(directoryCacheSize / 4)
        .maximumSize(directoryCacheSize)
        .expireAfterWrite(4, TimeUnit.HOURS) // Notice if someone hides a dir.
        .build();

    // The Administrator may bypass Share access control.
    skipShareAcl = Boolean.parseBoolean(
        config.getValue(CONFIG_SKIP_SHARE_ACL));
    log.log(Level.CONFIG, "skipShareAcl: {0}", skipShareAcl);

    // Add filters that may exclude older content.
    lastAccessTimeFilter = getFileTimeFilter(config,
        CONFIG_LAST_ACCESSED_DAYS, CONFIG_LAST_ACCESSED_DATE);
    lastModifiedTimeFilter = getFileTimeFilter(config,
        CONFIG_LAST_MODIFIED_DAYS, CONFIG_LAST_MODIFIED_DATE);

    monitorForUpdates = Boolean.parseBoolean(
        config.getValue(CONFIG_MONITOR_UPDATES));
    log.log(Level.CONFIG, "monitorForUpdates: {0}", monitorForUpdates);

    // How often to update file systems Status for Dashboard, in minutes.
    long minutes =
        Integer.parseInt(config.getValue(CONFIG_STATUS_UPDATE_INTERVAL_MINS));
    log.log(Level.CONFIG, "statusUpdateIntervalMinutes: {0}", minutes);
    statusUpdateIntervalMillis = TimeUnit.MINUTES.toMillis(minutes);

    // Verify that the startPaths are good.
    int validStartPaths = 0;
    for (Path startPath : startPaths) {
      try {
        validateStartPath(startPath, /* logging = */ true);
        validStartPaths++;
        updateStatus(startPath, Status.Code.NORMAL);
      } catch (IOException e) {
        log.log(Level.WARNING, "Unable to validate start path " + startPath, e);
        updateStatus(startPath, e);
      }
    }
    if (validStartPaths == 0) {
      throw new IOException("All start paths failed validation.");
    }

    // Create StatusSources of the sorted start paths for the Dashboard.
    Set<Path> statusSources = new TreeSet<Path>(new PathComparator());
    statusSources.addAll(fsStatus.keySet());
    for (Path source : statusSources) {
      context.addStatusSource(new FsStatusSource(source));
    }

    // Kick off a scheduled task to regularly update the statuses.
    statusUpdateService.schedule(new TimerTask() {
        @Override
        public void run() {
          try {
            updateAllStatus();
          } catch (RuntimeException e) {
            log.log(Level.WARNING, "Dashboard Status update interrupted.", e);
          }
        }
      }, statusUpdateIntervalMillis, statusUpdateIntervalMillis);
  }

  @Override
  public void destroy() {
    statusUpdateService.cancel();
    delegate.destroy();
  }

  /** Parses the collection of startPaths from the supplied sources. */
  @VisibleForTesting
  Set<Path> getStartPaths(String sources, String separator)
      throws IOException {
    if (separator.isEmpty()) {
      // No separator implies a single startPath.
      return ImmutableSet.of(delegate.getPath(sources));
    }
    ImmutableSet.Builder<Path> builder = ImmutableSet.builder();
    Iterable<String> startPoints = Splitter.on(separator)
        .trimResults().omitEmptyStrings().split(sources);
    for (String startPoint : startPoints) {
      Path startPath = delegate.getPath(startPoint);
      builder.add(startPath);
      log.log(Level.CONFIG, "startPath: {0}", startPath);
    }
    return builder.build();
  }

  /** Verify that a startPath is valid. */
  private void validateStartPath(Path startPath, boolean logging)
      throws IOException, InvalidConfigurationException {
    try {
      delegate.newDocId(startPath);
    } catch (IllegalArgumentException e) {
        throw new InvalidConfigurationException("The path " + startPath
             + " is not valid path - " + e.getMessage() + ".");
    }

    if (!crawlHiddenFiles && delegate.isHidden(startPath)) {
      throw new InvalidConfigurationException("The path " + startPath + " is "
          + "hidden. To crawl hidden content, you must set the configuration "
          + "property \"filesystemadaptor.crawlHiddenFiles\" to \"true\".");
    }

    // TODO(mifern): Using a path of \\host\ns\link\FolderA will be
    // considered non-DFS even though \\host\ns\link is a DFS link path.
    // This is OK for now since it will fail all three checks below and
    // will throw an InvalidConfigurationException.
    if (delegate.isDfsLink(startPath)) {
      Path dfsActiveStorage = delegate.resolveDfsLink(startPath);
      if (logging) {
        log.log(Level.INFO, "Using a DFS path resolved to {0}",
                dfsActiveStorage);
      }
      validateShare(startPath);
    } else if (delegate.isDfsNamespace(startPath)) {
      if (logging) {
        log.log(Level.INFO, "Using a DFS namespace {0}.", startPath);
      }
      for (Path link : delegate.enumerateDfsLinks(startPath)) {
        // Postpone full validation until crawl time.
        try {
          Path dfsActiveStorage = delegate.resolveDfsLink(link);
          if (logging) {
            log.log(Level.INFO, "DFS path {0} resolved to {1}",
                    new Object[] {link, dfsActiveStorage});
            // When called from init(), set the initial status of enumerated 
            // DFS links as unavailable, as we are not calling validateShare()
            // at this time. The actual status will be set when this is
            // called from the statusUpdateService or getDocContent().
            updateStatus(link, Status.Code.UNAVAILABLE);
          }
        } catch (IOException e) {
          log.log(Level.WARNING, "Unable to resolve DFS link " + startPath, e);
          updateStatus(link, e);
        }
      }
    } else if (startPath.equals(startPath.getRoot())) {
      if (logging) {
        log.log(Level.INFO, "Using a non-DFS path {0}", startPath);
      }
      validateShare(startPath);
    } else {
      // We currently only support a config path that is a root.
      // Non-root paths will fail to produce Acls for all the folders up
      // to the root from the configured path, so we limit configuration
      // only to root paths.
      throw new InvalidConfigurationException(
          "Invalid path " + startPath + ". Acceptable paths need to be"
          + " either \\\\host\\namespace or \\\\host\\namespace\\link"
          + " or \\\\host\\share.");
    }
  }

  /** Verify the path is available and we have access to it. */
  private void validateShare(Path sharePath) throws IOException {
    if (delegate.isDfsNamespace(sharePath)) {
      throw new AssertionError("validateShare can only be called "
          + "on DFS links or active storage paths");
    }

    // Verify that the adaptor has permission to read the contents of the root.
    try {
      delegate.newDirectoryStream(sharePath).close();
    } catch (AccessDeniedException e) {
      throw new IOException("Unable to list the contents of " + sharePath
          + ". This can happen if the Windows account used to crawl "
          + "the path does not have sufficient permissions.", e);
    } catch (NotDirectoryException e) {
      throw new InvalidConfigurationException("The path " + sharePath
          + " is not a directory. Acceptable paths need to be either "
          + "\\\\host\\namespace or \\\\host\\namespace\\link or "
          + "\\\\host\\shared directory.");
    } catch (FileNotFoundException e) {
      throw new InvalidConfigurationException("The path " + sharePath
          + " was not found.");
    } catch (NoSuchFileException e) {
      throw new InvalidConfigurationException("The path " + sharePath
          + " was not found.");
    } catch (IOException e) {
      throw new IOException("The path " + sharePath + " is not accessible. "
          + "The path does not exist, or it is not shared, or its hosting "
          + "file server is currently unavailable.", e);
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
    log.entering("FsAdaptor", "getDocIds", new Object[] {pusher});
    ImmutableList.Builder<Record> builder = ImmutableList.builder();
    for (Path startPath : startPaths) {
      DocId docid = delegate.newDocId(startPath);
      log.log(Level.FINE, "Pushing docid {0}", docid);
      builder.add(new Record.Builder(docid).setCrawlImmediately(true).build());
    }
    pusher.pushRecords(builder.build());
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

    if (!isVisibleDescendantOfRoot(doc)) {
      resp.respondNotFound();
      return;
    }

    // Check isEmpty first (nearly always true) to avoid calling getStartPath().
    if (!blockedPaths.isEmpty() && blockedPaths.contains(getStartPath(doc))) {
      throw new IllegalStateException("Skipping " + doc
          + " because its start path is blocked.");
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

    if (resultLinksToShare) {
      resp.setDisplayUrl(doc.toUri());
    }
    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("Creation Time", dateFormatter.get().format(
        new Date(attrs.creationTime().toMillis())));

    // TODO(mifern): Include extended attributes.

    if (delegate.isDfsNamespace(doc)) {
      try {      
        // Enumerate links in a namespace.
        getDfsNamespaceContent(doc, id, resp);
        updateStatus(doc, Status.Code.NORMAL);
      } catch (IOException e) {
        updateStatus(doc, e);
        throw e;
      }
    } else {
      // If we are at the root of a filesystem or share point, supply the
      // SHARE ACL. If it is a DFS Link, also include the DFS SHARE ACL.
      if (startPaths.contains(doc) || delegate.isDfsLink(doc)) {
        // TODO(bmj): Maybe have validateShare return the share ACLs it read.
        try {
          validateShare(doc);
          updateStatus(doc, Status.Code.NORMAL);
        } catch (IOException e) {
          updateStatus(doc, e);
          throw e;
        }
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
        getDirectoryContent(doc, id, lastAccessTime, resp);
      } else {
        getFileContent(doc, lastAccessTime, resp);
      }
    }
    log.exiting("FsAdaptor", "getDocContent");
  }

  /**
   * Returns the parent of a Path, or its root if it has no parent,
   * or null if already at root.
   *
   * UNC paths to DFS namespaces and DFS links behave somewhat oddly.
   * A DFS namespace contains one or more DFS links with a path like
   * \\host\namespace\link. However a call to Path.getParent() for
   * \\host\namespace\link does not return \\host\namespace; instead
   * it returns null. But, Path.getRoot() for \\host\namespace\link
   * does return \\host\namespace, which is exactly what I need.
   */
  private Path getParent(Path path) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      return parent;
    } else {
      Path root = path.getRoot();
      return (path.equals(root)) ? null : root;
    }
  }

  /* Populate the document ACL in the response. */
  private void getFileAcls(Path doc, Response resp) throws IOException {
    if (delegate.isDfsNamespace(doc)) {
      throw new AssertionError("getFileAcls can not be called on "
          + "DFS namespace paths");
      }
    final boolean isRoot = startPaths.contains(doc) || delegate.isDfsLink(doc);
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
      // inherit directly from the share ACL. Crawl up to node with share ACL.
      for (inheritFrom = doc;
          !startPaths.contains(inheritFrom) && !delegate.isDfsLink(inheritFrom);
          inheritFrom = getParent(inheritFrom)) {
        // Empty body.
      }
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
        if (indexFolders) {
          acl = builder.getAcl()
              .setInheritFrom(inheritFromDocId, CHILD_FOLDER_INHERIT_ACL)
              .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
        } else {
          // ACLs on noIndex documents are ignored, so don't supply one.
          acl = null;
        }
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
    resp.setNoIndex(!indexFolders);
    try (HtmlResponseWriter writer = createHtmlResponseWriter(resp)) {
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
  }

  /* Makes HTML document with links this directory's files and folder. */
  private void getDirectoryContent(Path doc, DocId docid,
      FileTime lastAccessTime, Response resp) throws IOException {
    resp.setNoIndex(!indexFolders);
    try (DirectoryStream<Path> files = delegate.newDirectoryStream(doc);
         HtmlResponseWriter writer = createHtmlResponseWriter(resp)) {
      writer.start(docid, getFileName(doc));
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
      writer.finish();
    } finally {
      setLastAccessTime(doc, lastAccessTime);
    }
  }

  /* Adds the file's content to the response. */
  private void getFileContent(Path doc, FileTime lastAccessTime, Response resp)
      throws IOException {
    resp.setContentType(delegate.probeContentType(doc));
    try (InputStream input = delegate.newInputStream(doc)) {
      copyStream(input, resp.getOutputStream());
    } finally {
      setLastAccessTime(doc, lastAccessTime);      
    }
  }

  /**
   * Copy contents of {@code in} to {@code out}.
   */
  private static void copyStream(InputStream in, OutputStream out)
      throws IOException {
    byte[] buffer = new byte[32 * 1024];
    int read;
    while ((read = in.read(buffer)) != -1) {
      out.write(buffer, 0, read);
    }
    out.flush();
  }

  /**
   * Sets the last access time for the file to the supplied {@code FileTime}.
   * Failure to preserve last access times can fool backup and archive systems
   * into thinking the file or folder has been recently accessed by a human,
   * preventing the movement of least recently used items to secondary storage.
   * </p>
   * If the adaptor is unable to restore the last access time for the file,
   * it is likely the traversal user does not have sufficient privileges to
   * write the file's attributes.  We therefore halt crawls on this volume
   * unless the administrator allows us to proceed even if file timestamps
   * might not be preserved.
   */
  private void setLastAccessTime(Path doc, FileTime lastAccessTime)
      throws IOException {
    if (preserveLastAccessTime == PreserveLastAccessTime.NEVER) {
      return;
    }
    try {
      delegate.setLastAccessTime(doc, lastAccessTime);
    } catch (AccessDeniedException e) {
      if (preserveLastAccessTime == PreserveLastAccessTime.ALWAYS) {
        // TODO(bmj): Make this message a localizable resource?
        String message = String.format("Unable to restore the last access time "
            + "for %1$s. This can happen if the Windows account used to crawl "
            + "the path does not have sufficient permissions to write file "
            + "attributes. If you do not wish to enforce preservation of the "
            + "last access time for files and folders as they are crawled, "
            + "please set the '%2$s' configuration property to '%3$s' or "
            + "'%4$s'.",
            new Object[] { doc.toString(), CONFIG_PRESERVE_LAST_ACCESS_TIME,
                PreserveLastAccessTime.IF_ALLOWED,
                PreserveLastAccessTime.NEVER });
        log.log(Level.WARNING, message, e);
        Path startPath = getStartPath(doc);
        updateStatus(startPath, Status.Code.ERROR, message);
        blockedPaths.add(startPath);
      } else {
        // This failure can be expected. We can have full permissions
        // to read but not write/update permissions.
        log.log(Level.FINER, "Unable to restore the last access time for {0}.",
                doc);
      }
    }
  }
    
  /** Returns the startPath that {@code doc} resides under. */
  private Path getStartPath(Path doc) throws IOException {
    for (Path startPath : startPaths) {
      if (doc.startsWith(startPath)) {
        return startPath;
      }
    }
    throw new IOException("Unable to determine the start path for " + doc);
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

  /** These are the cached entities in the isVisibleCache. */
  private static enum HiddenType {
      VISIBLE, HIDDEN, HIDDEN_UNDER, NOT_UNDER_STARTPATH
    };

  private static class Hidden {
    public HiddenType type;
    public Path hiddenBy;

    public Hidden(HiddenType type) {
      this.type = type;
    }

    public Hidden(HiddenType type, Path hiddenBy) {
      this.type = type;
      this.hiddenBy = hiddenBy;
    }
  }

  /**
   * Verifies that the file is a descendant of one of the startPaths,
   * and that it, nor none of its ancestors, is hidden.
   */
  @VisibleForTesting
  boolean isVisibleDescendantOfRoot(final Path doc) throws IOException {
    final Path dir;
    // I only want to cache directories, not regular files; so check
    // for hidden files directly, but cache its parent.
    if (delegate.isRegularFile(doc)) {
      if (!crawlHiddenFiles && delegate.isHidden(doc)) {
        log.log(Level.WARNING, "Skipping {0} because it is hidden.", doc);
        return false;
      }
      dir = getParent(doc);
    } else {
      dir = doc;
    }

    // Cache isVisibleDecendantOfRoot results for directories.
    Hidden hidden;
    try {
      hidden = isVisibleCache.get(dir, new Callable<Hidden>() {
          @Override
          public Hidden call() throws IOException {
            for (Path file = dir; file != null; file = getParent(file)) {
              if (!crawlHiddenFiles && delegate.isHidden(file)) {
                if (doc == file) {
                  return new Hidden(HiddenType.HIDDEN);
                } else {
                  return new Hidden(HiddenType.HIDDEN_UNDER, file);
                }
              }
              if (startPaths.contains(file)) {
                return new Hidden(HiddenType.VISIBLE);
              }
            }
            return new Hidden(HiddenType.NOT_UNDER_STARTPATH);
          }
        });
    } catch (ExecutionException e) {
      if (e.getCause() instanceof IOException) {
        throw (IOException) (e.getCause());
      } else {
        throw new IOException(e);
      }
    }

    if (hidden.type == HiddenType.VISIBLE) {
      return true;
    } else if (hidden.type == HiddenType.HIDDEN) {
      log.log(Level.WARNING, "Skipping {0} because it is hidden.", doc);
    } else if (hidden.type == HiddenType.HIDDEN_UNDER) {
      log.log(Level.WARNING,
              "Skipping {0} because it is hidden under {1}.",
              new Object[] { doc, hidden.hiddenBy });
    } else if (hidden.type == HiddenType.NOT_UNDER_STARTPATH) {
      log.log(Level.WARNING,
              "Skipping {0} because it is not a descendant of a start path.",
              doc);
    }
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

  // Path instances from different FileSystem providers are not
  // directly comparable, so use string compare on the pathnames.
  // This is used to provide a sorted list of StatusSources.
  private static class PathComparator implements Comparator<Path> {
    @Override
    public int compare(Path p1, Path p2) {
      if (p1 == p2) {
        return 0;
      } else {
        return (p1.toString().compareTo(p2.toString()));
      }
    }
  }

  private static class FsStatus implements Status {
    private final Status.Code code;
    private final String message;

    FsStatus(Status.Code code) {
      this(code, null);
    }

    FsStatus(Status.Code code, String message) {
      this.code = code;
      this.message = message;
    }

    FsStatus(Exception e) {
      this(Status.Code.ERROR,
           (e.getMessage() != null) ? e.getMessage() : e.toString());
    }

    @Override
    public Status.Code getCode() {
      return code;
    }

    @Override
    public String getMessage(Locale locale) {
      // TODO(bmj): These messages come from thrown Exceptions, many of which
      // originate from outside of our code base. We could try to localize
      // our own error messages used to form the Exception, but at the time
      // it is thrown, we don't know this locale. And by the time we get here,
      // many of our messages have had formatted parameter substitution.
      return message;
    }
  }

  private class FsStatusSource implements StatusSource {
    private final Path source;

    FsStatusSource(Path source) {
      this.source = source;
    }

    @Override
    public String getName(Locale locale) {
      // Locale is ignored, because pathnames are not localized.
      return source.toString();
    }

    @Override
    public Status retrieveStatus() {
      FsStatus status = fsStatus.get(source);
      return (status != null) ? status : new FsStatus(Status.Code.UNAVAILABLE);
    }
  }

  private void updateStatus(Path path, Status.Code code) {
    fsStatus.put(path, new FsStatus(code));
    log.log(Level.FINE, "Dashboard Status of {0} set to {1}",
        new Object[] { path, code });
  }

  private void updateStatus(Path path, Status.Code code, String message) {
    fsStatus.put(path, new FsStatus(code, message));
    log.log(Level.FINE, "Dashboard Status of {0} set to {1}: {2}",
        new Object[] { path, code, message });
  }

  private void updateStatus(Path path, Exception e) {
    FsStatus status = new FsStatus(e);
    fsStatus.put(path, status);
    log.log(Level.FINE, "Dashboard Status of {0} set to {1}: {2}", new Object[]
        { path, status.getCode(), status.getMessage(Locale.ROOT) });
  }

  private void updateAllStatus() {
    log.log(Level.FINE, "Updating Dashboard Status");
    for (Path path : fsStatus.keySet()) {
      if (blockedPaths.contains(path)) {
        // Leave the current status as is.
        continue;
      }
      try {
        validateStartPath(path, /* logging = */ false);
        updateStatus(path, Status.Code.NORMAL);
      } catch (IOException e) {
        updateStatus(path, e);
      } catch (InvalidConfigurationException e) {
        updateStatus(path, e);
      }
    }
  }

  private static Map<DocId, AuthzStatus> allDeny(Collection<DocId> ids) {
    ImmutableMap.Builder<DocId, AuthzStatus> result
        = ImmutableMap.<DocId, AuthzStatus>builder();
    for (DocId id : ids) {
      result.put(id, AuthzStatus.DENY); 
    }
    return result.build();  
  }

  private static final DocId FOR_ACL_IS_AUTHORIZED = new DocId("whatever");
  // Used to get around pre-condition requiring all parts of chain other
  // than root to have inheritFrom be set.

  private class AccessChecker implements AuthzAuthority {
    public Map<DocId, AuthzStatus> isUserAuthorized(AuthnIdentity userIdentity,
        Collection<DocId> ids) throws IOException {
      if (null == userIdentity) {
        log.info("null identity to authorize");
        return allDeny(ids);  // TODO: consider way to permit public
      }
      UserPrincipal user = userIdentity.getUser();
      if (null == user) {
        log.info("null user to authorize");
        return allDeny(ids);  // TODO: consider way to permit public
      }
      log.log(Level.INFO, "about to authorize {0}", user);
      ImmutableMap.Builder<DocId, AuthzStatus> result
          = ImmutableMap.<DocId, AuthzStatus>builder();
      for (DocId id : ids) {
        try {
          log.log(Level.FINE, "about to authorize {0} for {1}",
              new Object[]{user, id});
          List<Acl> aclChain = makeAclChain(delegate.getPath(id.getUniqueId()));
          AuthzStatus decision = Acl.isAuthorized(userIdentity, aclChain);
          log.log(Level.FINE,
              "authorization decision {0} for user {1} and doc {2}",
              new Object[]{decision, user, id});
          result.put(id, decision);
        } catch (IOException ioe) {
          log.log(Level.WARNING, "could not get ACL", ioe);
          result.put(id, AuthzStatus.INDETERMINATE);
        }
      }
      log.log(Level.FINEST, "done with authorizing {0}", user);
      return result.build();
    }

    /** Our chain will consist of (1) DFS-link ACL, (2) active-storage ACL,
     *  and (3) combined ACL of entire file system folder hiearachy with leaf
     *  ACL. If there is no DFS-link in chain then we skip that ACL.
     */
    private List<Acl> makeAclChain(final Path leaf) throws IOException {
      if (delegate.isDfsNamespace(leaf)) {
        String emsg = "late-binding for DFS Namespace not supported: " + leaf;
        throw new IOException(emsg);
      }
      final Path aclRoot = getAclRoot(leaf);
      log.log(Level.FINEST, "ACL root of {0} is {1}",
          new Object[]{leaf, aclRoot});
      // Check exists after getAclRoot determines if leaf is under a startpath.
      if (!isFileOrFolder(leaf)) {
        throw new IOException("Not a file or folder: " + leaf);
      }
      List<Acl> aclChain = new ArrayList<Acl>(3);
      ShareAcls shareAcls = readShareAcls(aclRoot); // blows up on DFS namespace
      if (shareAcls.dfsShareAcl != null) {
        aclChain.add(shareAcls.dfsShareAcl);
      }
      aclChain.add(shareAcls.shareAcl);
      aclChain.add(makeLeafAcl(leaf));
      log.log(Level.FINEST, "ACL chain for {0} is {1}",
          new Object[]{leaf, aclChain});
      return aclChain;
    }
  
    private Path getAclRoot(final Path leaf) throws IOException {
      for (Path current = leaf; current != null; current = getParent(current)) {
        if (startPaths.contains(current) || delegate.isDfsLink(current)) {
          return current;  // We found root of the access control chain.
        } 
      }
      throw new IOException("Not under a start path: " + leaf);
    }
  
    private Acl makeLeafAcl(final Path leaf) throws IOException {
      AclFileAttributeViews aclViews = delegate.getAclViews(leaf);
      AclBuilder builder = new AclBuilder(leaf, aclViews.getCombinedAclView(),
          supportedWindowsAccounts, builtinPrefix, namespace);
      Acl leafAcl = builder.getFlattenedAcl()
          .setInheritFrom(FOR_ACL_IS_AUTHORIZED)
          .setInheritanceType(InheritanceType.LEAF_NODE)
          .setEverythingCaseInsensitive()
          .build();
      return leafAcl;
    }
  }

  /**
   * Call default main for adaptors.
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    AbstractAdaptor.main(new FsAdaptor(), args);
  }
}
