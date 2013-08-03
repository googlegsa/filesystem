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

import com.google.common.base.Preconditions;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.DocIdPusher.Record;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

class FsMonitor {
  private static final Logger log
      = Logger.getLogger(FsMonitor.class.getName());

  private final FileDelegate delegate;
  private final DocIdPusher pusher;
  private final PushThread pushThread;
  private final BlockingQueue<Path> queue;
  private final int maxFeedSize;
  private final int maxLatencyMinutes;

  public FsMonitor(FileDelegate delegate, DocIdPusher pusher,
      int maxFeedSize, int maxLatencyMinutes) {
    Preconditions.checkNotNull(delegate, "the delegate may not be null");
    Preconditions.checkNotNull(pusher, "the DocId pusher may not be null");
    Preconditions.checkArgument(maxFeedSize > 0,
        "the maxFeedSize must be greater than zero");
    Preconditions.checkArgument(maxLatencyMinutes > 0,
        "the maxLatencyMinutes must be greater than zero");
    this.delegate = delegate;
    this.pusher = pusher;
    this.maxFeedSize = maxFeedSize;
    this.maxLatencyMinutes = maxLatencyMinutes;
    queue = new LinkedBlockingQueue<Path>(20 * maxFeedSize);
    pushThread = new PushThread();
  }

  public BlockingQueue<Path> getQueue() {
    return queue;
  }

  public void start() {
    pushThread.start();
  }

  public synchronized void destroy() {
    pushThread.terminate();
    try {
      pushThread.join();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private class PushThread extends Thread {
    public PushThread() {
    }

    public void terminate() {
      interrupt();
    }

    public void run() {
      log.entering("FsMonitor", "PushThread.run");
      Set<Path> docs = new HashSet<Path>();
      Set<Record> records = new HashSet<Record>();
      while (true) {
        try {
          BlockingQueueBatcher.take(queue, docs, maxFeedSize,
              maxLatencyMinutes, TimeUnit.MINUTES);
          createRecords(records, docs);
          log.log(Level.FINER, "Sending crawl immediately records: {0}",
              records);
          pusher.pushRecords(records);
          records.clear();
          docs.clear();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          break;
        }
      }
      log.exiting("FsMonitor", "PushThread.run");
    }

    private void createRecords(Set<Record> records, Collection<Path> docs) {
      for (Path doc : docs) {
        try {
          records.add(new DocIdPusher.Record.Builder(delegate.newDocId(doc))
              .setCrawlImmediately(true).build());
        } catch (IOException e) {
          log.log(Level.WARNING, "Unable to create new DocId for " + doc, e);
        }
      }
    }
  }
}

