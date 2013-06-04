// Copyright 2011 Google Inc. All Rights Reserved.
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

import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

// TODO(mifern): Support\Verify that we can handle \\host\C$ shares.
// TODO(mifern): Support\Verify that we can handle \\host only shares.
//   And decide what we want to discover within \\host only shares.

/**
 * Simple example adaptor that serves files from the local filesystem.
 */
public class FsAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(FsAdaptor.class.getName());

  private Path rootPath;

  public FsAdaptor() {
  }

  @Override
  public void initConfig(Config config) {
    // Setup default configuration values. The user is allowed to override them.

    // Create a new configuration key for letting the user configure this
    // adaptor.
    config.addKey("filesystemadaptor.src", ".");
    // Change the default to automatically provide unzipped zip contents to the
    // GSA.
    config.overrideKey("adaptor.autoUnzip", "true");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    // TODO(mifern): Read the config information.
    String source = context.getConfig().getValue("filesystemadaptor.src");
    rootPath = Paths.get(source);
    // TODO(mifern): Verify that we have a valid path and that we has access.
    return;
  }

  // TODO(mifern): Change crawl to use graph traversal.
  // TODO(mifern): In Windows only change '\' to '/'.
  @Override
  public void getDocIds(DocIdPusher pusher) throws IOException,
      InterruptedException {
    pushDocIds(pusher, rootPath);
  }

  // TODO(mifern): Remove this when change to graph traversal.
  private void pushDocIds(DocIdPusher pusher, Path parent)
      throws IOException, InterruptedException {
    ArrayList<DocId> docIds = new ArrayList<DocId>();
    for (Path file : Files.newDirectoryStream(parent)) {
      if (Files.isRegularFile(file)) {
        DocId docId = new DocId(file.toString());
        log.info("Sending " + docId + " to feed.");
        docIds.add(docId);
      } else if (Files.isDirectory(file)) {
        pushDocIds(pusher, file);
      }
    }
    pusher.pushDocIds(docIds);
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    DocId id = req.getDocId();
    // TODO(mifern): We need to normalize the doc path.
    String docPath = id.getUniqueId();

    Path doc = Paths.get(docPath);

    if (!isFileDescendantOfRoot(doc)) {
      log.log(Level.WARNING,
          "Skipping {0} since it is not a descendant of {1}.",
          new Object[] { doc, rootPath });
      resp.respondNotFound();
      return;
    }

    // Populate the document metadata.
    // TODO(mifern): What about these?
    //resp.setContentType(String contentType);
    //resp.setSecure(boolean secure);
    //resp.setNoIndex(boolean noIndex);
    //resp.setNoFollow(boolean noFollow);
    //resp.setNoArchive(boolean noArchive);
    BasicFileAttributes attrs = Files.readAttributes(doc,
        BasicFileAttributes.class);
    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("CreationTime",
        new Date(attrs.creationTime().toMillis()).toString());
    resp.addMetadata("LastAccessTime",
        new Date(attrs.lastAccessTime().toMillis()).toString());
    resp.addMetadata("FileSize", Long.toString(attrs.size()));
    // TODO(mifern): Include SpiConstants.PROPNAME_FOLDER.
    // TODO(mifern): Include Filesystem-specific properties (length, etc).
    // TODO(mifern): Include extended attributes (Java 7 java.nio.file.attributes).
    // TODO(mifern): Include extended office attributes.

    // Populate the document ACL.

    // Populate the document content.
    InputStream input = Files.newInputStream(doc);
    try {
      IOHelper.copyStream(input, resp.getOutputStream());
    } finally {
      input.close();
    }
  }
/*
  private String normalizeDocPath(String doc) {
    File docFile = new File(doc).getCanonicalFile();
  }
*/
  private boolean isFileDescendantOfRoot(Path file) {
    while (file != null) {
      if (file.equals(rootPath)) {
        return true;
      }
      file = file.getParent();
    }
    return false;
  }

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new FsAdaptor(), args);
  }
}
