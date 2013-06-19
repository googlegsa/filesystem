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
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
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

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private AdaptorContext context;

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
    this.context = context;
    // TODO(mifern): Read the config information.
    String source = context.getConfig().getValue("filesystemadaptor.src");
    rootPath = Paths.get(source);
    // TODO(mifern): Verify that we have a valid path and that we has access.
    return;
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
    log.entering("FsAdaptor", "getDocContent",
        new Object[] {req, resp});
    DocId id = req.getDocId();
    // TODO(mifern): We need to normalize the doc path and confirm that the 
    // normalized path is the same of the requested path.
    String docPath = id.getUniqueId();

    Path doc = Paths.get(docPath);
    final String docName = getPathName(doc);

    if (!isFileDescendantOfRoot(doc)) {
      log.log(Level.WARNING,
          "Skipping {0} since it is not a descendant of {1}.",
          new Object[] { doc, rootPath });
      resp.respondNotFound();
      return;
    }

    if (!Files.isRegularFile(doc) && !Files.isDirectory(doc)) {
      // This is a non-supported file type.
      resp.respondNotFound();
      return;
    }

    // TODO(mifern): What should the display URL be?
    //resp.setDisplayUrl(URI displayUrl);

    // Populate the document metadata.
    BasicFileAttributes attrs = Files.readAttributes(doc,
        BasicFileAttributes.class);
    final DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
    final FileTime lastAccessTime = attrs.lastAccessTime();

    resp.setLastModified(new Date(attrs.lastModifiedTime().toMillis()));
    resp.addMetadata("Creation Time", df.format(
        new Date(attrs.creationTime().toMillis())));
    resp.addMetadata("Last Access Time",  df.format(
        new Date(lastAccessTime.toMillis())));
    resp.addMetadata("File Name", docName);
    if (!Files.isDirectory(doc)) {
      // TODO(mifern): Do not set the content type for now.
      //resp.setContentType(Files.probeContentType(doc));
      resp.addMetadata("File Size", Long.toString(attrs.size()));
    }

    //populateExtendedAttributes(doc, resp);

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
          try {
            Files.setAttribute(doc, "lastAccessTime", lastAccessTime);
          } catch (Throwable e) {
            // This failure can be expected. We can have full permissions
            // to read but not write/update.
            log.log(Level.CONFIG,
                "Unable to update last access time for {0}.", doc);
          }
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
    }
    log.exiting("FsAdaptor", "getDocContent");
  }
/*
  private void populateExtendedAttributes(Path doc, Response resp) {
    try {
      UserDefinedFileAttributeView userView = Files.getFileAttributeView(doc,
          UserDefinedFileAttributeView.class);
      List<String> attribList = userView.list();
      if (attribList != null) {
        // TODO(mifern); Implement parsing the attributes
        // DocumentSummaryInformation & SummaryInformation.
        for (String name : attribList) {
          ByteBuffer buf = ByteBuffer.allocate(userView.size(name));
          userView.read(name, buf);
          buf.flip();
          String value = Charset.defaultCharset().decode(buf).toString();
          if (!Strings.isNullOrEmpty(value)) {
            resp.addMetadata(name, value);
          }
        }
      }
    } catch (UnsupportedOperationException e) {
      log.log(Level.FINE, "Extended attributes not supported for {0}.", doc);
    }
  }
*/

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
