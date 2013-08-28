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
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.text.DateFormat;
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
 * Simple example adaptor that serves files from the local filesystem.
 */
public class FsAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(FsAdaptor.class.getName());

  /** The config parameter name for the root path. */
  private static final String CONFIG_SRC = "filesystemadaptor.src";

  /** The config parameter name for the supported Windows accounts. */
  private static final String CONFIG_SUPPORTED_ACCOUNTS =
      "filesystemadaptor.supportedAccounts";

  private static final String SHARE_ACL_PREFIX = "shareAcl:";
  private static final String ALL_FOLDER_INHERIT_ACL_PREFIX = "allFoldersAcl:";
  private static final String ALL_FILE_INHERIT_ACL_PREFIX = "allFiles:";
  private static final String CHILD_FOLDER_INHERIT_ACL_PREFIX =
      "childFoldersAcl:";
  private static final String CHILD_FILE_INHERIT_ACL_PREFIX =
      "childFilesAcl:";

  /** The config parameter name for the prefix for BUILTIN groups. */
  private static final String CONFIG_BUILTIN_PREFIX =
      "filesystemadaptor.builtinGroupPrefix";

  /** The config parameter name for the max incremental batch size. */
  private static final String CONFIG_MAX_INCREMENTAL_LATENCY_MINUTES =
      "filesystemadaptor.maxIncrementalLatencyMinutes";

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

  private AdaptorContext context;
  private Path rootPath;
  private DocId rootPathDocId;
  private FileDelegate delegate;

  private FsMonitor monitor;

  public FsAdaptor() {
    // At the moment, we only support Windows.
    if (System.getProperty("os.name").startsWith("Windows")) {
      delegate = new WindowsFileDelegate();
    } else {
      throw new IllegalStateException(
          "Windows is the only supported platform.");
    }
  }

  @Override
  public void initConfig(Config config) {
    config.addKey(CONFIG_SRC, null);
    config.addKey(CONFIG_SUPPORTED_ACCOUNTS,
        "BUILTIN\\Administrators,\\Everyone,BUILTIN\\Users,BUILTIN\\Guest,"
        + "NT AUTHORITY\\INTERACTIVE,NT AUTHORITY\\Authenticated Users");
    config.addKey(CONFIG_BUILTIN_PREFIX, "BUILTIN\\");
    config.addKey(CONFIG_MAX_INCREMENTAL_LATENCY_MINUTES, "5");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    this.context = context;
    String source = context.getConfig().getValue(CONFIG_SRC);
    if (source.isEmpty()) {
      throw new IOException("The configuration value " + CONFIG_SRC
          + " is empty. Please specify a valid root path.");
    }
    rootPath = Paths.get(source);
    if (!isSupportedPath(rootPath)) {
      throw new IOException("The path " + rootPath + " is not a valid path. "
          + "The path does not exist or it is not a file or directory.");
    }
    log.log(Level.CONFIG, "rootPath: {0}", rootPath);

    builtinPrefix = context.getConfig().getValue(CONFIG_BUILTIN_PREFIX);
    log.log(Level.CONFIG, "builtinPrefix: {0}", builtinPrefix);

    String accountsStr =
        context.getConfig().getValue(CONFIG_SUPPORTED_ACCOUNTS);
    supportedWindowsAccounts = Collections.unmodifiableSet(Sets.newHashSet(
        Splitter.on(',').trimResults().split(accountsStr)));
    log.log(Level.CONFIG, "supportedWindowsAccounts: {0}",
        supportedWindowsAccounts);

    int maxFeed = Integer.parseInt(
        context.getConfig().getValue("feed.maxUrls"));
    int maxLatencyMinutes = Integer.parseInt(
        context.getConfig().getValue(CONFIG_MAX_INCREMENTAL_LATENCY_MINUTES));

    rootPathDocId = delegate.newDocId(rootPath);
    monitor = new FsMonitor(delegate, context.getDocIdPusher(), maxFeed,
        maxLatencyMinutes);
    delegate.startMonitorPath(rootPath, monitor.getQueue());
    monitor.start();
  }

  @Override
  public void destroy() {
    delegate.destroy();
    monitor.destroy();
    monitor = null;
  }

  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException,
      IOException {
    log.entering("FsAdaptor", "getDocIds", new Object[] {pusher, rootPath});
    pusher.pushDocIds(Arrays.asList(delegate.newDocId(rootPath)));
    log.exiting("FsAdaptor", "getDocIds");
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    log.entering("FsAdaptor", "getDocContent",
        new Object[] {req, resp});
    DocId id = req.getDocId();
    String docPath = id.getUniqueId();
    Path doc = Paths.get(docPath);
    final boolean docIsDirectory = Files.isDirectory(doc,
        LinkOption.NOFOLLOW_LINKS);

    if (!id.equals(delegate.newDocId(doc))) {
      log.log(Level.WARNING,
          "The {0} is not a valid id generated by the adaptor.", id);
      resp.respondNotFound();
      return;
    }

    if (!isDescendantOfRoot(doc)) {
      log.log(Level.WARNING,
          "Skipping {0} since it is not a descendant of {1}.",
          new Object[] { doc, rootPath });
      resp.respondNotFound();
      return;
    }

    if (!isSupportedPath(doc)) {
      log.log(Level.WARNING, "The path {0} is not a supported file type.",
          doc);
      resp.respondNotFound();
      return;
    }

    // Populate the document metadata.
    BasicFileAttributes attrs = Files.readAttributes(doc,
        BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    final FileTime lastAccessTime = attrs.lastAccessTime();

    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("Creation Time", dateFormatter.get().format(
        new Date(attrs.creationTime().toMillis())));
    resp.addMetadata("Last Access Time",  dateFormatter.get().format(
        new Date(lastAccessTime.toMillis())));
    if (!docIsDirectory) {
      resp.setContentType(Files.probeContentType(doc));
      resp.addMetadata("File Size", Long.toString(attrs.size()));
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

    AclBuilder builder = new AclBuilder(doc, delegate.getAclView(doc),
        supportedWindowsAccounts, builtinPrefix);

    DocId inheritDocId;
    if (isRoot) {
      inheritDocId = newNamedResourceDocId(rootPathDocId, SHARE_ACL_PREFIX);
    } else if (docIsDirectory) {
      inheritDocId = newNamedResourceDocId(parentDocId,
          CHILD_FOLDER_INHERIT_ACL_PREFIX);
    } else {
      inheritDocId = newNamedResourceDocId(parentDocId,
          CHILD_FILE_INHERIT_ACL_PREFIX);
    }
    Acl acl = builder.getAcl(inheritDocId);
    log.log(Level.FINEST, "Setting Acl: doc: {0}, acl: {1}",
        new Object[] { doc, acl });
    resp.setAcl(acl);

    // Push the additional Acls for a folder.
    if (docIsDirectory) {
      Map<DocId, Acl> resources = new HashMap<DocId, Acl>();
      DocId parentFolderInherit;
      DocId parentFileInherit;

      if (isRoot) {
        AclFileAttributeView shareAclView = delegate.getShareAclView(doc);
        AclBuilder builderShare = new AclBuilder(doc, shareAclView,
            supportedWindowsAccounts, builtinPrefix);
        resources.put(newNamedResourceDocId(id, SHARE_ACL_PREFIX),
            builderShare.getAcl(null));
        parentFolderInherit = null;
        parentFileInherit = null;
      } else {
        parentFolderInherit =
            newNamedResourceDocId(parentDocId, ALL_FOLDER_INHERIT_ACL_PREFIX);
        parentFileInherit =
            newNamedResourceDocId(parentDocId, ALL_FILE_INHERIT_ACL_PREFIX);
      }

      resources.put(newNamedResourceDocId(id, ALL_FOLDER_INHERIT_ACL_PREFIX),
          builder.getInheritableByAllDesendentFoldersAcl(parentFolderInherit));
      resources.put(newNamedResourceDocId(id, ALL_FILE_INHERIT_ACL_PREFIX),
          builder.getInheritableByAllDesendentFilesAcl(parentFileInherit));
      resources.put(newNamedResourceDocId(id, CHILD_FOLDER_INHERIT_ACL_PREFIX),
          builder.getInheritableByChildFoldersOnlyAcl(parentFolderInherit));
      resources.put(newNamedResourceDocId(id, CHILD_FILE_INHERIT_ACL_PREFIX),
          builder.getInheritableByChildFilesOnlyAcl(parentFileInherit));

      new Thread(new ThreadSetAcl(context.getDocIdPusher(), resources, doc))
          .start();
    }

    // TODO(mifern): Flip these two conditionals to
    // "if (docIsDirectory) { ... } else { ... }" to eliminate the use of
    // Files.isRegularFile(doc).
    // TODO(mifern): The conditional
    // "if (Files.isRegularFile(file) || Files.isDirectory(file))" below
    // should be changed to use isValidPath.
    // Populate the document content.
    if (Files.isRegularFile(doc, LinkOption.NOFOLLOW_LINKS)) {
      InputStream input = Files.newInputStream(doc);
      try {
        IOHelper.copyStream(input, resp.getOutputStream());
      } finally {
        try {
          input.close();
        } finally {
          try {
            Files.setAttribute(doc, "lastAccessTime", lastAccessTime,
                LinkOption.NOFOLLOW_LINKS);
          } catch (IOException e) {
            // This failure can be expected. We can have full permissions
            // to read but not write/update permissions.
            log.log(Level.CONFIG,
                "Unable to update last access time for {0}.", doc);
          }
        }
      }
    } else if (docIsDirectory) {
      HtmlResponseWriter writer = createHtmlResponseWriter(resp);
      writer.start(id, getPathName(doc));
      for (Path file : Files.newDirectoryStream(doc)) {
        if (isSupportedPath(file)) {
          writer.addLink(delegate.newDocId(file), getPathName(file));
        }
      }
      writer.finish();
    }
    log.exiting("FsAdaptor", "getDocContent");
  }

  private HtmlResponseWriter createHtmlResponseWriter(Response response)
      throws IOException {
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, context.getDocIdEncoder(),
        Locale.ENGLISH);
  }

  @VisibleForTesting
  String getPathName(Path file) {
    return file.toFile().getName();
  }

  private boolean isSupportedPath(Path p) {
    return Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) ||
        Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS);
  }

  private boolean isDescendantOfRoot(Path file) {
    while (file != null) {
      if (file.equals(rootPath)) {
        return true;
      }
      file = file.getParent();
    }
    return false;
  }

  private DocId newNamedResourceDocId(DocId id, String idPrefix) {
    return new DocId(idPrefix + id.getUniqueId());
  }

  // TODO(mifern): Consider using BlockingQueueBatcher and only have one
  // thread. The current implementation creates a thread for every folder
  // being crawled, the thread does a send then exists. This may be an issue
  // if we crawl a folder that has 100's of subfolders since we'll create
  // 100's of short lived threads.
  // NOTE: Using a thread to send a named resource may not be the final
  // approach.
  // NOTE: An an API may be exposed in the Adaptor Library that lets us
  // send a named resources from Response and uses BlockingQueueBatcher
  // behind the scenes.
  private class ThreadSetAcl implements Runnable {
    private DocIdPusher pusher;
    private Map<DocId, Acl> resources;
    private Path doc;

    public ThreadSetAcl(DocIdPusher pusher, Map<DocId, Acl> resources,
        Path doc) {
      this.pusher = pusher;
      this.resources = resources;
      this.doc = doc;
    }

    public void run() {
      try {
        log.log(Level.FINEST,
            "Pushing named resources: doc: {0}, resources: {1}",
            new Object[] { doc, resources });
        pusher.pushNamedResources(resources);
      } catch (InterruptedException e) {
        log.log(Level.WARNING, "Unable to set ACLs for {0}.", doc);
        Thread.currentThread().interrupt();
      }
    }
  }

  private class FsMonitor {
    private final DocIdPusher pusher;
    private final PushThread pushThread;
    private final BlockingQueue<Path> queue;
    private final int maxFeedSize;
    private final int maxLatencyMinutes;

    public FsMonitor(FileDelegate delegate, DocIdPusher pusher,
        int maxFeedSize, int maxLatencyMinutes) {
      Preconditions.checkNotNull(delegate, "the delegate may not be null");
      Preconditions.checkNotNull(pusher, "the DocId pusher may not be null");
      Preconditions.checkArgument(maxFeedSize > 0,
          "the maxFeedSize must be greater than zero");
      Preconditions.checkArgument(maxLatencyMinutes > 0,
          "the maxLatencyMinutes must be greater than zero");
      this.pusher = pusher;
      this.maxFeedSize = maxFeedSize;
      this.maxLatencyMinutes = maxLatencyMinutes;
      queue = new LinkedBlockingQueue<Path>(20 * maxFeedSize);
      pushThread = new PushThread();
    }

    public BlockingQueue<Path> getQueue() {
      return queue;
    }

    public void start() {
      pushThread.start();
    }

    public synchronized void destroy() {
      pushThread.terminate();
      try {
        pushThread.join();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    private class PushThread extends Thread {
      public PushThread() {
      }

      public void terminate() {
        interrupt();
      }

      public void run() {
        log.entering("FsMonitor", "PushThread.run");
        Set<Path> docs = new HashSet<Path>();
        Set<Record> records = new HashSet<Record>();
        while (true) {
          try {
            BlockingQueueBatcher.take(queue, docs, maxFeedSize,
                maxLatencyMinutes, TimeUnit.MINUTES);
            createRecords(records, docs);
            log.log(Level.FINER, "Sending crawl immediately records: {0}",
                records);
            pusher.pushRecords(records);
            records.clear();
            docs.clear();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            break;
          }
        }
        log.exiting("FsMonitor", "PushThread.run");
      }

      private void createRecords(Set<Record> records, Collection<Path> docs) {
        for (Path doc : docs) {
          try {
            if (isSupportedPath(doc)) {
              records.add(new DocIdPusher.Record.Builder(delegate.newDocId(doc))
                  .setCrawlImmediately(true).build());
            } else {
              log.log(Level.INFO,
                  "Skipping path {0}. It is not a supported file type.", doc);
            }
          } catch (IOException e) {
            log.log(Level.WARNING, "Unable to create new DocId for " + doc, e);
          }
        }
      }
    }
  }

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new FsAdaptor(), args);
  }
}
