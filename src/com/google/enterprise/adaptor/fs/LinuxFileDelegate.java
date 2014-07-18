// Copyright 2014 Google Inc. All Rights Reserved.
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
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

class LinuxFileDelegate extends NioFileDelegate {
  private static final Logger log
      = Logger.getLogger(LinuxFileDelegate.class.getName());

  @Override
  public AclFileAttributeViews getAclViews(Path doc) throws IOException {
    // TODO(mifern): Add Acl support.
    return new AclFileAttributeViews(
        new SimpleAclFileAttributeView(Collections.<AclEntry>emptyList()),
        new SimpleAclFileAttributeView(Collections.<AclEntry>emptyList()));
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc) throws IOException {
    // TODO(mifern): Add share Acl support.
    return new SimpleAclFileAttributeView(Collections.<AclEntry>emptyList());
  }

  @Override
  public AclFileAttributeView getDfsShareAclView(Path doc) {
    // TODO(mifern): Add DFS support.
    return new SimpleAclFileAttributeView(Collections.<AclEntry>emptyList());
  }

  @Override
  public Path getDfsUncActiveStorageUnc(Path doc) throws IOException {
    // TODO(mifern): Add DFS support.
    return null;
  }

  @Override
  public void startMonitorPath(Path watchPath, AsyncDocIdPusher pusher)
      throws IOException {
    // TODO(mifern): Start monitoring.
  }

  @Override
  public void stopMonitorPath() {
    // TODO(mifern): Not sure what monitoring we will have but we need
    //  to stop it.
  }

  @Override
  public void destroy() {
    // TODO(mifern): Destroy any resrouces created for monitoring.
  }
}
