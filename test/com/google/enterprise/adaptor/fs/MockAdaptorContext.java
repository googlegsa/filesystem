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

import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.AsyncDocIdPusher;
import com.google.enterprise.adaptor.AuthnAuthority;
import com.google.enterprise.adaptor.AuthzAuthority;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.ExceptionHandler;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.SensitiveValueDecoder;
import com.google.enterprise.adaptor.Session;
import com.google.enterprise.adaptor.StatusSource;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.util.ArrayList;
import java.util.List;

/**
 * Mock of {@link AdaptorContext}.
 */
class MockAdaptorContext implements AdaptorContext {
  private final Config config = new Config();
  private final DocIdPusher docIdPusher = new AccumulatingDocIdPusher();
  private final AsyncDocIdPusher asycDocIdPusher =
      new AccumulatingAsyncDocIdPusher();
  private final DocIdEncoder docIdEncoder = new MockDocIdCodec();
  private final List<StatusSource> statusSources =
      new ArrayList<StatusSource>();

  @Override
  public Config getConfig() {
    return config;
  }

  @Override
  public DocIdPusher getDocIdPusher() {
    return docIdPusher;
  }

  @Override
  public AsyncDocIdPusher getAsyncDocIdPusher() {
    return asycDocIdPusher;
  }

  @Override
  public DocIdEncoder getDocIdEncoder() {
    return docIdEncoder;
  }

  @Override
  public void addStatusSource(StatusSource source) {
    statusSources.add(source);
  }

  @Override
  public void setGetDocIdsFullErrorHandler(ExceptionHandler handler) {
    throw new UnsupportedOperationException();
  }

  @Override
  public ExceptionHandler getGetDocIdsFullErrorHandler() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setGetDocIdsIncrementalErrorHandler(
      ExceptionHandler handler) {
    throw new UnsupportedOperationException();
  }

  @Override
  public ExceptionHandler getGetDocIdsIncrementalErrorHandler() {
    throw new UnsupportedOperationException();
  }

  @Override
  public SensitiveValueDecoder getSensitiveValueDecoder() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HttpContext createHttpContext(String path, HttpHandler handler) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Session getUserSession(HttpExchange ex, boolean create) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setPollingIncrementalLister(PollingIncrementalLister lister) {
  }

  @Override
  public void setAuthnAuthority(AuthnAuthority authnAuthority) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setAuthzAuthority(AuthzAuthority authzAuthority) {
    throw new UnsupportedOperationException();
  }
}
