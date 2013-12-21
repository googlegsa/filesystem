// Copyright 2009 Google Inc.
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

import static com.google.enterprise.adaptor.fs.AclView.user;
import static com.google.enterprise.adaptor.fs.AclView.group;

import static java.nio.file.attribute.AclEntryFlag.*;
import static java.nio.file.attribute.AclEntryPermission.*;
import static java.nio.file.attribute.AclEntryType.*;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.DirectoryStream;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

class MockFile {
  static final String SEPARATOR = "/";
  static final FileTime defaultFileTime = FileTime.fromMillis(10000);
  static final AclFileAttributeView fullAccessAclView = 
      new AclView(group("Everyone").type(ALLOW)
          .perms(READ_DATA, READ_ATTRIBUTES, READ_NAMED_ATTRS, READ_ACL)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT));
  static final AclFileAttributeView emptyAclView = new AclView();

  private MockFile parent;
  private String name;
  private boolean exists = true;
  private boolean isHidden = false;
  private boolean isRegularFile;
  private boolean isDirectory;
  private List<MockFile> directoryContents;
  private Path dfsUncActiveStorageUnc;
  private AclFileAttributeView dfsShareAclView;
  private AclFileAttributeView shareAclView;
  private AclFileAttributeView aclView;
  private AclFileAttributeView inheritedAclView;
  private FileTime creationTime = defaultFileTime;
  private FileTime lastAccessTime = defaultFileTime;
  private FileTime lastModifiedTime = defaultFileTime;
  private String contentType;
  private byte[] fileContents;

  /**
   * Create a regular file with the specified {@code name}.
   *
   * @param name the name of the file
   */
  MockFile(String name) {
    this(name, false);
  }

  /**
   * Create a file or directory with the specified {@code name}.
   *
   * @param name the name of the file or directory
   * @param isDirectory true if this is a directory, false if regular file
   */
  MockFile(String name, boolean isDirectory) {
    Preconditions.checkNotNull(name, "name cannot be null");
    this.name = name;
    this.isRegularFile = !isDirectory;
    this.isDirectory = isDirectory;
    if (isDirectory) {
      directoryContents = new ArrayList<MockFile>();
    } else {
      setFileContents("Contents of " + name);
    }
  }

  /**
   * Add the supplied files/directories as children of this MockFile.
   * This automatically sets isDirectory and resets isRegularFile on this
   * MockFile, and registers this file as the parent of all the children.
   */
  MockFile addChildren(MockFile... children) {
    for (MockFile child : children) {
      child.parent = this;
      directoryContents.add(child);
    }
    return this;
  }

  /**
   * Returns the child of the given name.
   */
  MockFile getChild(String name) throws FileNotFoundException {
    Preconditions.checkNotNull(name, "name cannot be null");
    Iterator<MockFile> it = directoryContents.iterator();
    while (it.hasNext()) {
      MockFile f = it.next();
      if (f.name.equals(name)) {
        return f;
      }
    }
    throw new FileNotFoundException(
        "no such file: " + getPath() + SEPARATOR + name);
  }

  /**
   * Remove this file.
   */
  void delete() {
    if (parent != null) {
      // Unlink from parent.
      Iterator<MockFile> it = parent.directoryContents.iterator();
      while (it.hasNext()) {
        if (it.next() == this) {
          it.remove();
          break;
        }
      }
    }
    if (isDirectory) {
      // TODO: If this is insufficient, delete recursively.
      // But after this, getChild() will fail, so we should be OK.
      directoryContents.clear();
    }
    exists = isDirectory = isRegularFile = isHidden = false;
    parent = null;
    name = null;
  }

  /**
   * Return the path to this file or directory.
   */
  String getPath() {
    if (parent == null) {
      return name;
    } else {
      return parent.getPath() + SEPARATOR + name;
    }
  }

  MockFile setName(String name) {
    Preconditions.checkNotNull(name, "name cannot be null");
    this.name = name;
    return this;
  }

  /**
   * Return the name to this file or directory.
   */
  String getName() {
    return name;
  }

  /**
   * Return the parent directory of this file or directory,
   * or null if there is no parent.
   */
  MockFile getParent() {
    return parent;
  }

  boolean isDirectory() throws IOException {
    return isDirectory;
  }

  /** If false, maybe a directory, pipe, device, broken link, hidden, etc. */
  MockFile setIsRegularFile(boolean isRegularFile) {
    this.isRegularFile = isRegularFile;
    return this;
  }

  boolean isRegularFile() throws IOException {
    return isRegularFile;
  }

  MockFile setExists(boolean exists) {
    this.exists = exists;
    return this;
  }

  boolean exists() throws IOException {
    return this.exists;
  }

  MockFile setIsHidden(boolean isHidden) {
    this.isHidden = isHidden;
    return this;
  }

  boolean isHidden() throws IOException {
    return isHidden;
  }

  MockFile setCreationTime(FileTime creationTime) {
    Preconditions.checkNotNull(creationTime, "time cannot be null");
    this.creationTime = creationTime;
    return this;
  }

  FileTime getCreateTime() throws IOException {
    return creationTime;
  }

  MockFile setLastModifiedTime(FileTime lastModifiedTime) {
    Preconditions.checkNotNull(lastModifiedTime, "time cannot be null");
    this.lastModifiedTime = lastModifiedTime;
    return this;
  }

  FileTime getLastModifiedTime() throws IOException {
    return lastModifiedTime;
  }

  /** Note that the adaptor calls this setter. */
  MockFile setLastAccessTime(FileTime lastAccessTime) throws IOException {
    Preconditions.checkNotNull(lastAccessTime, "time cannot be null");
    this.lastAccessTime = lastAccessTime;
    return this;
  }

  FileTime getLastAccessTime() throws IOException {
    return lastAccessTime;
  }

  BasicFileAttributes readBasicAttributes() throws IOException {
    return new MockBasicFileAttributes();
  }

  MockFile setDfsUncActiveStorageUnc(Path unc) {
    this.dfsUncActiveStorageUnc = unc;
    return this;
  }

  Path getDfsUncActiveStorageUnc() throws IOException {
    return dfsUncActiveStorageUnc;
  }

  MockFile setDfsShareAclView(AclFileAttributeView aclView) {
    this.dfsShareAclView = aclView;
    return this;
  }
  
  AclFileAttributeView getDfsShareAclView() throws IOException {
    return dfsShareAclView;
  }

  MockFile setShareAclView(AclFileAttributeView aclView) {
    this.shareAclView = aclView;
    return this;
  }

  AclFileAttributeView getShareAclView() throws IOException {
    return (shareAclView == null) ? fullAccessAclView : shareAclView;
  }

  MockFile setAclView(AclFileAttributeView aclView) {
    this.aclView = aclView;
    return this;
  }

  AclFileAttributeView getAclView() throws IOException {
    if (aclView == null) {
      return (parent == null) ? fullAccessAclView : emptyAclView;
    } else {
      return aclView;
    }
  }

  MockFile setInheritedAclView(AclFileAttributeView aclView) {
    this.inheritedAclView = aclView;
    return this;
  }

  AclFileAttributeView getInheritedAclView() throws IOException {
    if (inheritedAclView == null) {
      if (parent == null) {
        // root has no inherited ACL
        return emptyAclView;
      } else if (parent.parent == null) {
        // root's children inherit its ACL
        return parent.getAclView();	
      } else {
        // all other children inherit from their parent
        return parent.getInheritedAclView();
      }
    } else {
      return inheritedAclView;
    }
  }

  MockFile setContentType(String contentType) {
    this.contentType = contentType;
    return this;
  }

  String getContentType() throws IOException {
    return contentType;
  }

  MockFile setFileContents(String fileContents) {
    Preconditions.checkNotNull(fileContents, "fileContents cannot be null");
    setFileContents(fileContents.getBytes(Charsets.UTF_8));
    if (contentType == null) {
      contentType = "text/plain";
    }
    return this;
  }

  MockFile setFileContents(byte[] fileContents) {
    Preconditions.checkState(isRegularFile, "not a regular file %s", getPath());
    Preconditions.checkNotNull(fileContents, "fileContents cannot be null");
    this.fileContents = fileContents;
    return this;
  }

  InputStream newInputStream() throws IOException {
    Preconditions.checkState(isRegularFile, "not a regular file %s", getPath());
    return new ByteArrayInputStream(fileContents);
  }

  DirectoryStream<Path> newDirectoryStream() throws IOException {
    Preconditions.checkState(isDirectory, "not a directory %s", getPath());
    return new MockDirectoryStream(directoryContents);
  }

  @Override
  public String toString() {
    return getPath();
  }

  private class MockBasicFileAttributes implements BasicFileAttributes {

    @Override
    public Object fileKey() {
      return MockFile.this;
    }

    @Override
    public FileTime creationTime() {
      return creationTime;
    }

    @Override
    public FileTime lastAccessTime() {
      return lastAccessTime;
    }

    @Override
    public FileTime lastModifiedTime() {
      return lastModifiedTime;
    }

    @Override
    public boolean isDirectory() {
      return isDirectory;
    }

    @Override
    public boolean isRegularFile() {
      return isRegularFile;
    }

    @Override
    public boolean isOther() {
      return !(isDirectory || isRegularFile);
    }

    @Override
    public boolean isSymbolicLink() {
      return false;
    }

    @Override
    public long size() {
      if (isRegularFile && fileContents != null) {
        return fileContents.length;
      } else {
        return 0L;
      }
    }
  }

  private class MockDirectoryStream implements DirectoryStream<Path> {
    private Iterator<Path> iterator;

    MockDirectoryStream(List<MockFile> files) {
      ArrayList<Path> paths = new ArrayList<Path>();
      for (MockFile file : files) {
        paths.add(Paths.get(file.getPath()));
      }
      Collections.sort(paths);
      iterator = paths.iterator();
    }

    @Override
    public Iterator<Path> iterator() {
      Preconditions.checkState(iterator != null,
          "multiple attempts to get iterator");
      Iterator<Path> rtn = iterator;
      iterator = null;
      return rtn;
    }

    @Override
    public void close() {}
  }
}
