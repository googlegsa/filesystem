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

interface FileDelegate {
  /**
   * Returns an {@link AclFileAttributeView} that contains Acl for the
   * specified path.
   *
   * @param doc The file/folder to get the {@link AclFileAttributeView} for.
   */
  AclFileAttributeView getAclView(Path doc);

  /**
   * Creates a new {@link DocId}.
   *
   * @param doc The file/folder to get the {@link DocId} for.
   * @throws IOException
   */
  DocId newDocId(Path doc) throws IOException;
}
