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

import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.ExceptionHandler;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;

import java.util.Collection;
import java.util.Map;

/** Throws UnsupportedOperationException for all calls. */
class UnsupportedDocIdPusher implements DocIdPusher {

  @Override
  public DocId pushDocIds(Iterable<DocId> docIds)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public DocId pushDocIds(Iterable<DocId> docIds,
      ExceptionHandler handler)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Record pushRecords(Iterable<Record> records)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Record pushRecords(Iterable<Record> records,
      ExceptionHandler handler)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public DocId pushNamedResources(Map<DocId, Acl> resources)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public DocId pushNamedResources(Map<DocId, Acl> resources,
      ExceptionHandler handler)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public GroupPrincipal pushGroupDefinitions(
      Map<GroupPrincipal, ? extends Collection<Principal>> defs,
      boolean caseSensitive) throws InterruptedException {
    throw new UnsupportedOperationException();
  }

  @Override
  public GroupPrincipal pushGroupDefinitions(
      Map<GroupPrincipal, ? extends Collection<Principal>> defs,
      boolean caseSensitive, ExceptionHandler handler)
      throws InterruptedException {
    throw new UnsupportedOperationException();
  }
}
