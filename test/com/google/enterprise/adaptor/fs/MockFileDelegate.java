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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.enterprise.adaptor.AsyncDocIdPusher;
import com.google.enterprise.adaptor.DocId;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.DirectoryStream;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.BlockingQueue;
import java.util.Iterator;

class MockFileDelegate implements FileDelegate {

  private final MockFile root;

  MockFileDelegate(MockFile root) {
    Preconditions.checkNotNull(root, "root cannot be null");
    this.root = root;
  }

  /**
   * Returns the {@link MockFile} identified by the supplied {@link Path}.
   * @throws FileNotFoundException if the file is not found.
   */
  MockFile getFile(Path doc) throws FileNotFoundException {
    Preconditions.checkNotNull(doc, "doc cannot be null");
    MockFile file = root;
    Iterator<Path> iter = doc.iterator();
    if (doc.getRoot() != null) {
      // Using startsWith because Path adds a trailing backslash to
      // UNC roots.  The second check accounts for Windows Path
      // implementation flipping slashes on Unix paths.
      if (!(doc.getRoot().toString().startsWith(root.getPath()) ||
          root.getPath().equals(doc.getRoot().toString().replace('\\', '/')))) {
        throw new FileNotFoundException("not found: " + doc.toString());
      }
    } else if (iter.hasNext()) {
      if (!(root.getPath().equals(iter.next().toString()))) {
        throw new FileNotFoundException("not found: " + doc.toString());
      }
    }
    while (iter.hasNext()) {
      file = file.getChild(iter.next().toString());
    }
    return file;
  }

  @Override
  public Path getPath(String pathname) throws IOException {
    if (Strings.isNullOrEmpty(pathname)) {
      throw new InvalidPathException(pathname,
                                     "pathname cannot be null or empty");
    }
    return Paths.get(pathname);
  }

  @Override
  public boolean isDirectory(Path doc) throws IOException {
    try {
      return getFile(doc).isDirectory();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public boolean isRegularFile(Path doc) throws IOException {
    try {
      return getFile(doc).isRegularFile();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public boolean isHidden(Path doc) throws IOException {
    try {
      return getFile(doc).isHidden();
    } catch (FileNotFoundException e) {
      return false;
    }
  }

  @Override
  public BasicFileAttributes readBasicAttributes(Path doc) throws IOException {
    return getFile(doc).readBasicAttributes();
  }

  @Override
  public void setLastAccessTime(Path doc, FileTime time) throws IOException {
    getFile(doc).setLastAccessTime(time);
  }

  @Override
  public String probeContentType(Path doc) throws IOException {
    return getFile(doc).getContentType();
  }

  @Override
  public InputStream newInputStream(Path doc) throws IOException {
    return getFile(doc).newInputStream();
  }

  @Override
  public DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException {
    return getFile(doc).newDirectoryStream();
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    String id = doc.toString().replace('\\', '/');
    if (isDirectory(doc) && !id.endsWith("/")) {
      id += "/";
    }
    if (id.startsWith("//")) {
      // String.replaceFirst uses regular expression string and replacement
      // so they need to be escaped appropriately. The above String.replace
      // does NOT use expressions so regex escaping is not needed.
      id = id.replaceFirst("//", "\\\\\\\\");
    }
    return new DocId(id);
  }

  @Override
  public AclFileAttributeViews getAclViews(Path doc) throws IOException {
    MockFile file = getFile(doc);
    return new AclFileAttributeViews(file.getAclView(),
                                     file.getInheritedAclView());
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc) throws IOException {
    return root.getShareAclView();
  }

  @Override
  public AclFileAttributeView getDfsShareAclView(Path doc) throws IOException {
    return root.getDfsShareAclView();
  }

  @Override
  public Path getDfsUncActiveStorageUnc(Path doc) throws IOException {
    return root.getDfsUncActiveStorageUnc();
  }

  @Override
  public void startMonitorPath(Path watchPath, AsyncDocIdPusher pusher)
    throws IOException {
    // TODO (bmj): implementation
  }

  @Override
  public void stopMonitorPath() {
    // TODO (bmj): implementation
  }

  @Override
  public void destroy() {
    stopMonitorPath();
  }
}
