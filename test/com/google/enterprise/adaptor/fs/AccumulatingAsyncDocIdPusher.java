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

import com.google.common.collect.ImmutableSortedMap;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.AsyncDocIdPusher;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;

import java.util.Collections;
import java.util.logging.Logger;

class AccumulatingAsyncDocIdPusher extends AccumulatingDocIdPusher
    implements AsyncDocIdPusher {
  private static final Logger log
      = Logger.getLogger(AccumulatingAsyncDocIdPusher.class.getName());

  @Override
  public boolean pushDocId(DocId docId) {
    try {
      return pushDocIds(Collections.singleton(docId)) == null;
    } catch (InterruptedException e) {
      log.warning("Interrupted. Aborted getDocIds");
      Thread.currentThread().interrupt();
    }
    return false;
  }
  @Override
  public boolean pushRecord(DocIdPusher.Record record) {
    try {
      return pushRecords(Collections.singleton(record)) == null;
    } catch (InterruptedException e) {
      log.warning("Interrupted. Aborted getDocIds");
      Thread.currentThread().interrupt();
    }
    return false;
  }
  @Override
  public boolean pushNamedResource(DocId docId, Acl acl) {
    try {
      return pushNamedResources(ImmutableSortedMap.of(docId, acl)) == null;
    } catch (InterruptedException e) {
      log.warning("Interrupted. Aborted getDocIds");
      Thread.currentThread().interrupt();
    }
    return false;
  }
}
