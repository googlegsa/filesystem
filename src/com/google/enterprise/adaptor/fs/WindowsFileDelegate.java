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
import com.google.common.collect.ImmutableList;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.fs.WinApi.Netapi32Ex;
import com.google.enterprise.adaptor.fs.WinApi.Shlwapi;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.FILE_NOTIFY_INFORMATION;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.W32APIOptions;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

class WindowsFileDelegate extends NioFileDelegate {
  private static final Logger log
      = Logger.getLogger(WindowsFileDelegate.class.getName());

  private final WindowsAclFileAttributeViews aclViews
      = new WindowsAclFileAttributeViews();

  private MonitorThread monitorThread;
  private final Object monitorThreadLock = new Object();

  @Override
  public AclFileAttributeViews getAclViews(Path doc) throws IOException {
    return aclViews.getAclViews(doc);
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc) throws IOException {
    return aclViews.getShareAclView(doc);
  }

  @Override
  public AclFileAttributeView getDfsShareAclView(Path doc) {
    Netapi32Ex netapi32 = Netapi32Ex.INSTANCE;
    PointerByReference sd = new PointerByReference();
    IntByReference sdSize = new IntByReference();
    int rc = netapi32.NetDfsGetSecurity(doc.toString(),
        WinNT.DACL_SECURITY_INFORMATION |
            WinNT.PROTECTED_DACL_SECURITY_INFORMATION |
            WinNT.UNPROTECTED_DACL_SECURITY_INFORMATION,
        sd, sdSize);
    if (LMErr.NERR_Success != rc) {
      throw new Win32Exception(rc);
    }

    SECURITY_DESCRIPTOR_RELATIVEEx sdr =
        new SECURITY_DESCRIPTOR_RELATIVEEx(sd.getValue());
    WinNT.ACL dacl = sdr.getDiscretionaryACL();
    rc = netapi32.NetApiBufferFree(sd.getValue());
    if (LMErr.NERR_Success != rc) {
      throw new Win32Exception(rc);
    }

    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();
    for (WinNT.ACCESS_ACEStructure ace : dacl.getACEStructures()) {
      AclEntry entry = WindowsAclFileAttributeViews.newAclEntry(ace);
      if (entry != null) {
        builder.add(entry);
      }
    }

    List<AclEntry> acl = builder.build();
    log.log(Level.FINEST, "DFS share ACL for {0}: {1}",
        new Object[] { doc, acl });
    return new SimpleAclFileAttributeView(acl);
  }

  public static class ACLEx extends WinNT.ACL {
    private WinNT.ACCESS_ACEStructure[] ACEs;

    public ACLEx(Pointer p) {
      // Don't call super(p), call instead useMemory(p). The reason is
      // that super(p) will parse the security descriptor which is what
      // we're trying to avoid.
      useMemory(p);
      read();
      ACEs = new WinNT.ACCESS_ACEStructure[AceCount];
      int offset = size();
      for (int i = 0; i < AceCount; i++) {
        Pointer share = p.share(offset);
        byte aceType = share.getByte(0);
        WinNT.ACCESS_ACEStructure ace;
        switch (aceType) {
          case WinNT.ACCESS_ALLOWED_ACE_TYPE:
          case WinNT.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            ace = new WinNT.ACCESS_ALLOWED_ACE(share);
            break;
          case WinNT.ACCESS_DENIED_ACE_TYPE:
          case WinNT.ACCESS_DENIED_OBJECT_ACE_TYPE:
            ace = new WinNT.ACCESS_DENIED_ACE(share);
            break;
          default:
            throw new IllegalArgumentException("Unknwon ACE type " +
                aceType);
        }
        ACEs[i] = ace;
        offset += ace.AceSize;
      }
    }

    public WinNT.ACCESS_ACEStructure[] getACEStructures() {
      return ACEs;
    }
  }

  public static class SECURITY_DESCRIPTOR_RELATIVEEx extends
      WinNT.SECURITY_DESCRIPTOR_RELATIVE {
    private WinNT.ACL DACL;

    public SECURITY_DESCRIPTOR_RELATIVEEx(Pointer p) {
      // Don't call super(p), call instead useMemory(p). The reason is
      // that super(p) will parse the security descriptor which is what
      // we're trying to avoid.
      useMemory(p);
      read();
      if (Dacl != 0) {
        DACL = new ACLEx(getPointer().share(Dacl));
      }
    }

    public WinNT.ACL getDiscretionaryACL() {
      return DACL;
    }
  }

  @Override
  public Path getDfsUncActiveStorageUnc(Path doc) throws IOException {
    Netapi32Ex netapi32 = Netapi32Ex.INSTANCE;
    PointerByReference buf = new PointerByReference();
    int rc = netapi32.NetDfsGetInfo(doc.toString(), null, null, 3, buf);
    if (rc != LMErr.NERR_Success) {
      // Log this at INFO since we expect this when the adaptor is configured
      // for non-DFS root paths. Adaptor.init will call
      // getDfsUncActiveStorageUnc to check if the path is a DFS path.
      log.log(Level.INFO, "Unable to get DFS details for {0}. Code: {1}",
          new Object[] { doc, rc });
      return null;
    }

    Netapi32Ex.DFS_INFO_3 info = new Netapi32Ex.DFS_INFO_3(buf.getValue());
    netapi32.NetApiBufferFree(buf.getValue());

    // Find the active storage.
    String storageUnc = null;
    for (int i = 0; i < info.StorageInfos.length; i++) {
      Netapi32Ex.DFS_STORAGE_INFO storeInfo = info.StorageInfos[i];
      if (storeInfo.State.intValue() == Netapi32Ex.DFS_STORAGE_STATE_ONLINE) {
        storageUnc = String.format("\\\\%s\\%s", storeInfo.ServerName,
            storeInfo.ShareName);
        break;
      }
    }
    if (storageUnc == null) {
      throw new IOException("The DFS path " + doc +
          " does not have an active storage.");
    }

    return Paths.get(storageUnc);
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    File file = doc.toFile().getCanonicalFile();
    String id = file.getAbsolutePath().replace('\\', '/');
    if (file.isDirectory() && !id.endsWith("/")) {
      id += "/";
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

    CountDownLatch startSignal = new CountDownLatch(1);
    synchronized (monitorThreadLock) {
      monitorThread = new MonitorThread(watchPath, queue, startSignal);
      monitorThread.start();
    }
    // Wait for the monitor thread to start watching filesystem.
    try {
      startSignal.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
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
    private final CountDownLatch startSignal;
    private final HANDLE stopEvent;

    public MonitorThread(Path watchPath, BlockingQueue<Path> queue,
        CountDownLatch startSignal) {
      Preconditions.checkNotNull(watchPath, "the watchPath may not be null");
      Preconditions.checkNotNull(queue, "the queue may not be null");
      Preconditions.checkNotNull(startSignal,
                                 "the start signal may not be null");
      this.watchPath = watchPath;
      this.queue = queue;
      this.startSignal = startSignal;
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
      } finally {
        // Wake up caller, in case monitor fails to start up.
        startSignal.countDown();
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

        // Signal any waiting threads that the monitor is now active.
        startSignal.countDown();

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
            offerPath(changePath);
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
