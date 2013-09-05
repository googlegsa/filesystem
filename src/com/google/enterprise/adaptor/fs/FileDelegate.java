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
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;

interface FileDelegate {
  /**
   * Returns an {@link AclFileAttributeView} that contains the ACL for the
   * specified path.  The ACL contains no inherited permissions.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeView} for.
   * @return AclFileAttributeView of directly applied ACL entries
   */
  AclFileAttributeView getAclView(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains the inherited ACL
   * for the specified path. The ACL contains only permissions inherited
   * from the parent.
   * <p/>
   * Note that there is a distinct difference between a return value of
   * {@code null} and an empty ACL list. A return of {@code null} indicates
   * that the file did not inherit any aces from its parent.  An empty
   * {@code List} indicates that the file did inherit some permissions
   * from its parent, but inherited no {@code ACCESS_ALLOWED} or
   * {@code ACCESS_DENIED} permissions for user or group accounts.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeView} for.
   * @return AclFileAttributeView of inherited ACL entries, or {@code null}
   *         if there were no inherited ACLs entries.
   */
  AclFileAttributeView getInheritedAclView(Path doc) throws IOException;

  /**
   * Returns an {@link AclFileAttributeView} that contains share ACL for the
   * specified path.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeView} for.
   * @return AclFileAttributeView of ACL entries imposed by the share
   */
  AclFileAttributeView getShareAclView(Path doc) throws IOException;

  /**
   * Creates a new {@link DocId}.
   *
   * @param doc The file/folder to get the {@link DocId} for.
   * @throws IOException
   */
  DocId newDocId(Path doc) throws IOException;

  void startMonitorPath(Path watchPath, BlockingQueue<Path> queue)
      throws IOException;

  void stopMonitorPath();

  void destroy();
}
