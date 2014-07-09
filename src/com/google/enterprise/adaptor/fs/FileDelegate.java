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

import com.google.enterprise.adaptor.AsyncDocIdPusher;
import com.google.enterprise.adaptor.DocId;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;

interface FileDelegate {
  /**
   * Returns the real {@link Path} represented by the path string.
   * This is equivalent to {@code Paths.get(pathname)}.
   *
   * @param pathname the path string
   * @return the real Path
   */
  Path getPath(String pathname) throws IOException;

  /**
   * Returns {@code true} if the specified path represents
   * a directory, {@code false} otherwise.
   */
  boolean isDirectory(Path doc) throws IOException;

  /**
   * Returns {@code true} if the specified path represents
   * a regular file, {@code false} otherwise.
   */
  boolean isRegularFile(Path doc) throws IOException;

  /**
   * Returns {@code true} if the specified path represents
   * a hidden file or directory, {@code false} otherwise.
   */
  boolean isHidden(Path doc) throws IOException;

  /**
   * Returns the {@link BasicFileAttributes} for the file or directory.
   *
   * @param doc the file/folder to get the {@link BasicFileAttributes} for
   */
  BasicFileAttributes readBasicAttributes(Path doc) throws IOException;

  /**
   * Gets the lastAccess time for the file or directory.
   *
   * @param doc the file/folder to set the last accessed time on
   */
  FileTime getLastAccessTime(Path doc) throws IOException;

  /**
   * Sets the lastAccess time for the file or directory.
   *
   * @param doc the file/folder to set the last accessed time on
   * @param time the last access time
   */
  void setLastAccessTime(Path doc, FileTime time) throws IOException;

  /**
   * Probes the content type of a file.
   *
   * @param doc the file to get the content type
   * @return the content type of the file, or {@code null} if the
   * content type cannot be determined
   */
  String probeContentType(Path doc) throws IOException;
   
  /**
   * Returns an {@link InputStream} to read the file contents.
   *
   * @param doc the file to read
   * @return an InputStream to read the file contents
   */
  InputStream newInputStream(Path doc) throws IOException;

  /**
   * Returns a {@link DirectoryStream} to read the directory entries.
   *
   * @param doc the directory to list
   * @return an DirectoryStream to read the directory entries
   */
  DirectoryStream<Path> newDirectoryStream(Path doc) throws IOException;

  /**
   * Returns the active storage UNC path of a DFS UNC path.
   *
   * @param doc The DFS UNC path to get the storage for.
   * @returns the backing storage path, or null if doc is not a DFS path
   */
  Path getDfsUncActiveStorageUnc(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeViews} that contains the directly
   * applied and inherited {@link AclFileAttributeView} for the specified path.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeViews} for.
   * @return AclFileAttributeViews for the specified path
   */
  AclFileAttributeViews getAclViews(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains share Acl for the
   * specified path.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeView} for.
   */
  AclFileAttributeView getShareAclView(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains share Acl for the
   * specified DFS namespace.
   *
   * @param doc A DFS namespace to get the {@link AclFileAttributeView} for.
   */
  AclFileAttributeView getDfsShareAclView(Path doc) throws IOException;

  /**
   * Creates a new {@link DocId}.
   *
   * @param doc The file/folder to get the {@link DocId} for.
   * @throws IOException
   */
  DocId newDocId(Path doc) throws IOException;

  void startMonitorPath(Path watchPath, AsyncDocIdPusher pusher)
      throws IOException;

  void stopMonitorPath();

  void destroy();
}
