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

import com.google.common.base.Strings;
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
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
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

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private AdaptorContext context;

  private Path rootPath;

  public FsAdaptor() {
  }

  @Override
  public void initConfig(Config config) {
    // Setup default configuration values. The user is allowed to override them.
    config.addKey(CONFIG_SRC, ".");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    this.context = context;
    String source = context.getConfig().getValue(CONFIG_SRC);
    if (Strings.isNullOrEmpty(source)) {
      String message = "The configuration value " + CONFIG_SRC
          + " is empty. Please specific a valid root path.";
      log.severe(message);
      throw new IOException(message);
    }
    rootPath = Paths.get(source);
    log.log(Level.CONFIG, "rootPath: {0}", rootPath);
  }

  // TODO(mifern): In Windows only change '\' to '/'.
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    log.entering("FsAdaptor", "getDocIds", new Object[] {pusher, rootPath});
    // TODO(mifern): rootPath was verified in the config but the directory
    // could have changed so we need to verify access again.
    pusher.pushDocIds(Arrays.asList(new DocId(rootPath.toString())));
    log.exiting("FsAdaptor", "getDocIds");
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    DocId id = req.getDocId();
    // TODO(mifern): We need to normalize the doc path and confirm that the 
    // normalized path is the same of the requested path.
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
    final FileTime lastAccessTime = attrs.lastAccessTime();

    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("CreationTime",
        new Date(attrs.creationTime().toMillis()).toString());
    resp.addMetadata("LastAccessTime",
        new Date(lastAccessTime.toMillis()).toString());
    resp.addMetadata("FileSize", Long.toString(attrs.size()));
    // TODO(mifern): Include SpiConstants.PROPNAME_FOLDER.
    // TODO(mifern): Include Filesystem-specific properties (length, etc).
    // TODO(mifern): Include extended attributes (Java 7 java.nio.file.attributes).
    // TODO(mifern): Include extended office attributes.

    // Populate the document ACL.

    // Populate the document content.
    if (Files.isRegularFile(doc)) {
      InputStream input = Files.newInputStream(doc);
      try {
        IOHelper.copyStream(input, resp.getOutputStream());
      } finally {
        try {
          input.close();
        } finally {
          Files.setAttribute(doc, "lastAccessTime", lastAccessTime);
        }
      }
    } else if (Files.isDirectory(doc)) {
      HtmlResponseWriter writer = createHtmlResponseWriter(resp);
      writer.start(id, getPathName(doc));
      for (Path file : Files.newDirectoryStream(doc)) {
        if (Files.isRegularFile(file) || Files.isDirectory(file)) {
          writer.addLink(new DocId(file.toString()), getPathName(file));
        }
      }
      writer.finish();
    } else {
      // This is a non-supported file type.
      resp.respondNotFound();
    }
  }

  private HtmlResponseWriter createHtmlResponseWriter(Response response)
      throws IOException {
    Writer writer = new OutputStreamWriter(response.getOutputStream(),
        CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, context.getDocIdEncoder(),
        Locale.ENGLISH);
  }
  
  private String getPathName(Path file) {
    return file.getName(file.getNameCount() - 1).toString();
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
