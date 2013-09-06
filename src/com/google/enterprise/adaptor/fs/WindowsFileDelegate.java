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

import com.sun.jna.Native;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.FILE_NOTIFY_INFORMATION;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.win32.W32APIOptions;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WindowsFileDelegate implements FileDelegate {
  private static final Logger log
      = Logger.getLogger(WindowsFileDelegate.class.getName());

  private final WindowsAclFileAttributeViews aclViews
      = new WindowsAclFileAttributeViews();

  private MonitorThread monitorThread;
  private final Object monitorThreadLock = new Object();

  public WindowsFileDelegate() {
  }

  @Override
  public AclFileAttributeViews getAclViews(Path doc) throws IOException {
    return aclViews.getAclViews(doc);
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc) throws IOException {
    return aclViews.getShareAclView(doc);
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    File file = doc.toFile().getCanonicalFile();
    String id = file.getAbsolutePath().replace('\\', '/');
    if (file.isDirectory()) {
      if (!id.endsWith("/")) {
        id += "/";
      }
    }
    if (id.startsWith("//")) {
      // String.replaceFirst uses regular expression string and replacement
      // so they need to be escaped appropriately. The above String.replace
      // does NOT use expressions so regex escaping is not needed.
      id = id.replaceFirst("//", "\\\\\\\\");
    }
    return new DocId(id);
  }

  @Override
  public void startMonitorPath(Path watchPath, BlockingQueue<Path> queue)
      throws IOException {
    // Stop the current running monitor thread.
    stopMonitorPath();

    if (!Files.isDirectory(watchPath, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("Could not monitor " + watchPath
          + ". The path is not a valid directory.");
    }

    synchronized (monitorThreadLock) {
      monitorThread = new MonitorThread(watchPath, queue);
      monitorThread.start();
    }
  }

  @Override
  public void stopMonitorPath() {
    synchronized (monitorThreadLock) {
      if (monitorThread != null) {
        monitorThread.shutdown();
        monitorThread = null;
      }
    }
  }

  private static class MonitorThread extends Thread {
    private final Path watchPath;
    private final BlockingQueue<Path> queue;
    private final HANDLE stopEvent;

    public MonitorThread(Path watchPath, BlockingQueue<Path> queue) {
      Preconditions.checkNotNull(watchPath, "the watchPath may not be null");
      Preconditions.checkNotNull(queue, "the queue may not be null");
      this.watchPath = watchPath;
      this.queue = queue;
      stopEvent = Kernel32.INSTANCE.CreateEvent(null, false, false, null);
    }

    public void shutdown() {
      Kernel32Ex klib = Kernel32Ex.INSTANCE;
      klib.SetEvent(stopEvent);
      boolean interrupt = false;
      while (true) {
        try {
          join();
          break;
        } catch (InterruptedException ex) {
          interrupt = true;
        }
      }
      if (interrupt) {
        Thread.currentThread().interrupt();
      }
      klib.CloseHandle(stopEvent);
    }

    public void run() {
      log.entering("WindowsFileDelegate", "MonitorThread.run", watchPath);
      try {
        runMonitorLoop();
      } catch (IOException e) {
        log.log(Level.WARNING, "Unable to monitor " + watchPath, e);
      }
      log.exiting("WindowsFileDelegate", "MonitorThread.run", watchPath);
    }

    private void runMonitorLoop() throws IOException {
      Kernel32Ex klib = Kernel32Ex.INSTANCE;
      int mask = Kernel32.FILE_SHARE_READ | Kernel32.FILE_SHARE_WRITE |
          Kernel32.FILE_SHARE_DELETE;
      HANDLE handle = klib.CreateFile(watchPath.toString(),
          Kernel32.FILE_LIST_DIRECTORY, mask, null, Kernel32.OPEN_EXISTING,
          Kernel32.FILE_FLAG_BACKUP_SEMANTICS | Kernel32.FILE_FLAG_OVERLAPPED,
          null);
      if (Kernel32.INVALID_HANDLE_VALUE.equals(handle)) {
        throw new IOException("Unable to open " + watchPath
            + ". GetLastError: " + klib.GetLastError());
      }
      try {
        runMonitorLoop(handle);
      } finally {
        klib.CloseHandle(handle);
      }
    }

  /**
   * Runs a loop that monitors for file change events or a stop event.
   *
   * @param handle The handle to read changs from
   * @throws IOException on error
   */
    private void runMonitorLoop(HANDLE handle) throws IOException {
      Kernel32Ex klib = Kernel32Ex.INSTANCE;
      Kernel32.OVERLAPPED ol = new Kernel32.OVERLAPPED();

      final FILE_NOTIFY_INFORMATION info = new FILE_NOTIFY_INFORMATION(4096);
      int notifyFilter = Kernel32.FILE_NOTIFY_CHANGE_SECURITY |
          Kernel32.FILE_NOTIFY_CHANGE_CREATION |
          Kernel32.FILE_NOTIFY_CHANGE_LAST_WRITE |
          Kernel32.FILE_NOTIFY_CHANGE_ATTRIBUTES |
          Kernel32.FILE_NOTIFY_CHANGE_DIR_NAME |
          Kernel32.FILE_NOTIFY_CHANGE_FILE_NAME;

      Kernel32.OVERLAPPED_COMPLETION_ROUTINE changesCallback =
          new Kernel32.OVERLAPPED_COMPLETION_ROUTINE() {
            public void callback(int errorCode, int nBytesTransferred,
                Kernel32.OVERLAPPED ol) {
              log.entering("WindowsFileDelegate", "changesCallback",
                  new Object[] { errorCode, nBytesTransferred });
              if (errorCode == W32Errors.ERROR_SUCCESS) {
                try {
                  handleChanges(info);
                } catch (IOException e) {
                  log.log(Level.WARNING,
                      "Error processing file change notifications.", e);
                }
              } else if (errorCode == W32Errors.ERROR_NOTIFY_ENUM_DIR) {
                // An error of ERROR_NOTIFY_ENUM_DIR means that there was
                // a notification buffer overflows which can cause some 
                // notifications to be lost.
                log.log(Level.INFO,
                    "There was a buffer overflow during file monitoring. " +
                    "Some file update notifications may have been lost.");
              } else {
                log.log(Level.WARNING,
                    "Unable to read data notification data. errorCode: {0}",
                    errorCode);
              }
              log.exiting("WindowsFileDelegate", "changesCallback");
            }
          };

      while (true) {
        if (!klib.ReadDirectoryChangesW(handle, info, info.size(),
            true, notifyFilter, null, ol, changesCallback)) {
          throw new IOException("Unable to open " + watchPath
              + ". GetLastError: " + klib.GetLastError());
        }

        log.log(Level.FINER, "Waiting for notifications.");
        int waitResult = klib.WaitForSingleObjectEx(stopEvent,
            Kernel32.INFINITE, true);
        log.log(Level.FINER, "Got notification. waitResult: {0}", waitResult);

        if (waitResult == Kernel32Ex.WAIT_IO_COMPLETION) {
          log.log(Level.FINEST,
              "WaitForSingleObjectEx returned WAIT_IO_COMPLETION. " +
              "A notification was sent to the monitor callback.");
          continue;
        } else if (waitResult == WinBase.WAIT_OBJECT_0) {
          log.log(Level.FINE,
              "Terminate event has been set, ending file monitor.");
          return;
        } else {
          throw new IOException(
              "Unexpected result from WaitForSingleObjectEx: " + waitResult +
              ". GetLastError: " + klib.GetLastError());
        }
      }
    }

    private void handleChanges(FILE_NOTIFY_INFORMATION info)
        throws IOException {
      info.read();
      do {
        Path changePath = watchPath.resolve(info.getFilename());
        switch (info.Action) {
          case Kernel32.FILE_ACTION_MODIFIED:
            log.log(Level.FINEST, "Modified: {0}", changePath);
            break;
          case Kernel32.FILE_ACTION_ADDED:
          case Kernel32.FILE_ACTION_RENAMED_NEW_NAME:
            log.log(Level.FINEST, "Added: {0}", changePath);
            offerPath(changePath.getParent());
            break;
          case Kernel32.FILE_ACTION_REMOVED:
          case Kernel32.FILE_ACTION_RENAMED_OLD_NAME:
            log.log(Level.FINEST, "Removed: {0}", changePath);
            offerPath(changePath);
            offerPath(changePath.getParent());
            break;
          default:
            // Nothing to do here.
            break;
        }
        info = info.next();
      } while (info != null);
    }

    private void offerPath(Path path) {
      if (!queue.offer(path)) {
        log.log(Level.INFO, "Unable to add path {0} to push queue. " +
            "Incremental update notification will be lost.", path);
      }
    }
  }

  private interface Kernel32Ex extends Kernel32 {
    Kernel32Ex INSTANCE = (Kernel32Ex) Native.loadLibrary("Kernel32",
        Kernel32Ex.class, W32APIOptions.UNICODE_OPTIONS);

    public static final int WAIT_IO_COMPLETION = 0x000000C0;

    int WaitForSingleObjectEx(HANDLE hHandle, int dwMilliseconds,
        boolean bAlertable);
  }

  @Override
  public void destroy() {
    stopMonitorPath();
  }
}
