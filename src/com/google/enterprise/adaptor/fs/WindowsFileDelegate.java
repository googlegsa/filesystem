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

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Files;
import java.nio.file.Path;

public class WindowsFileDelegate implements FileDelegate {
  public WindowsFileDelegate() {
  }

  @Override
  public AclFileAttributeView getAclView(Path doc) {
    return Files.getFileAttributeView(doc, AclFileAttributeView.class);
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    File file = doc.toFile().getCanonicalFile();
    String id = file.getAbsolutePath().replace('\\', '/');
    id = id.replace('\\', '/');
    if (file.isDirectory()) {
      if (!id.endsWith("/")) {
        id += "/";
      }
    }
    return new DocId(id);
  }
}
