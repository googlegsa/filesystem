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

import com.google.enterprise.adaptor.DocId;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.BlockingQueue;

/**
 * A {@link FileDelegate} implementation on top of Java NIO.
 * This acts as a base class for other OS-specific implementations,
 * such as {@link WindowsFileDelegate}.
 */
abstract class NioFileDelegate implements FileDelegate {

  @Override
  public Path getPath(String pathname) throws IOException {
    return Paths.get(pathname).toRealPath(LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public boolean isDirectory(Path doc) throws IOException {
    return Files.isDirectory(doc, LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public boolean isRegularFile(Path doc) throws IOException {
    return Files.isRegularFile(doc, LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public boolean isHidden(Path doc) throws IOException {
    return Files.isHidden(doc);
  }

  @Override
  public BasicFileAttributes readBasicAttributes(Path doc) throws IOException {
    return Files.readAttributes(doc, BasicFileAttributes.class);
  }

  @Override
  public void setLastAccessTime(Path doc, FileTime time) throws IOException {
    Files.setAttribute(doc, "lastAccessTime", time, LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public String probeContentType(Path doc) throws IOException {
    return Files.probeContentType(doc);
  }

  @Override
  public InputStream newInputStream(Path doc) throws IOException {
    return Files.newInputStream(doc);
  }

  @Override
  public DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException {
    return Files.newDirectoryStream(doc);
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    Path realPath = doc.toRealPath(LinkOption.NOFOLLOW_LINKS);
    String id = realPath.toString();
    if (isDirectory(realPath) && !id.endsWith("/")) {
      id += "/";
    }
    return new DocId(id);
  }
}
