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
import com.google.common.collect.Sets;
import com.google.enterprise.adaptor.DocId;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.Netapi32;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.ACCESS_ACEStructure;
import com.sun.jna.platform.win32.WinNT.ACL;
import com.sun.jna.platform.win32.WinNT.FILE_NOTIFY_INFORMATION;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.WinNT.SECURITY_DESCRIPTOR;
import com.sun.jna.platform.win32.WinNT.SECURITY_DESCRIPTOR_RELATIVE;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WindowsFileDelegate implements FileDelegate {
  private static final Logger log
      = Logger.getLogger(WindowsFileDelegate.class.getName());

  /** This pattern parses a UNC path to get the host and share details. */
  private static final Pattern UNC_PATTERN =
      Pattern.compile("^\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)");

  /** The set of SID_NAME_USE which are groups and not users. */
  private static final Set<Integer> GROUP_SID_TYPES =
      Collections.unmodifiableSet(Sets.newHashSet(
        SID_NAME_USE.SidTypeAlias, SID_NAME_USE.SidTypeGroup,
            SID_NAME_USE.SidTypeWellKnownGroup));

  /** The set of SID_NAME_USE which are user and not groups. */
  private static final Set<Integer> USER_SID_TYPES =
      Collections.unmodifiableSet(Sets.newHashSet(SID_NAME_USE.SidTypeUser));

  /** The map of Acl permissions from NT to AclEntryPermission. */
  private static final Map<Integer, AclEntryPermission> ACL_PERMS_MAP =
      Collections.unmodifiableMap(new HashMap<Integer, AclEntryPermission>() {
          {
            put(WinNT.FILE_READ_DATA, AclEntryPermission.READ_DATA);
            put(WinNT.FILE_READ_ATTRIBUTES,
                AclEntryPermission.READ_ATTRIBUTES);
            put(WinNT.FILE_READ_EA, AclEntryPermission.READ_NAMED_ATTRS);
            put(WinNT.READ_CONTROL, AclEntryPermission.READ_ACL);
            put(WinNT.FILE_WRITE_DATA, AclEntryPermission.WRITE_DATA);
            put(WinNT.FILE_APPEND_DATA, AclEntryPermission.APPEND_DATA);
            put(WinNT.FILE_WRITE_ATTRIBUTES,
                AclEntryPermission.WRITE_ATTRIBUTES);
            put(WinNT.FILE_WRITE_EA, AclEntryPermission.WRITE_NAMED_ATTRS);
            put(WinNT.WRITE_DAC, AclEntryPermission.WRITE_ACL);
            put(WinNT.WRITE_OWNER, AclEntryPermission.WRITE_OWNER);
            put(WinNT.DELETE, AclEntryPermission.DELETE);
            put(WinNT.FILE_DELETE_CHILD, AclEntryPermission.DELETE_CHILD);
            put(WinNT.SYNCHRONIZE, AclEntryPermission.SYNCHRONIZE);
            put(WinNT.FILE_EXECUTE, AclEntryPermission.EXECUTE);
          }
      });

  /** The map of Acl entry flags from NT to AclEntryFlag. */
  private static final Map<Byte, AclEntryFlag> ACL_FLAGS_MAP =
      Collections.unmodifiableMap(new HashMap<Byte, AclEntryFlag>() {
          {
            put(WinNT.OBJECT_INHERIT_ACE, AclEntryFlag.FILE_INHERIT);
            put(WinNT.CONTAINER_INHERIT_ACE, AclEntryFlag.DIRECTORY_INHERIT);
            put(WinNT.INHERIT_ONLY_ACE, AclEntryFlag.INHERIT_ONLY);
            put(WinNT.NO_PROPAGATE_INHERIT_ACE,
                AclEntryFlag.NO_PROPAGATE_INHERIT);
          }
      });

  /** The map of Acl entry type from NT to AclEntryType. */
  private static final Map<Byte, AclEntryType> ACL_TYPE_MAP =
      Collections.unmodifiableMap(new HashMap<Byte, AclEntryType>() {
          {
            put(WinNT.ACCESS_ALLOWED_ACE_TYPE, AclEntryType.ALLOW);
            put(WinNT.ACCESS_DENIED_ACE_TYPE, AclEntryType.DENY);
          }
      });

  private MonitorThread monitorThread;
  private final Object monitorThreadLock = new Object();

  public WindowsFileDelegate() {
  }

  @Override
  public AclFileAttributeView getAclView(Path doc) {
    return Files.getFileAttributeView(doc, AclFileAttributeView.class,
        LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public AclFileAttributeView getShareAclView(Path doc)
      throws IOException, UnsupportedOperationException {
    if (Shlwapi.INSTANCE.PathIsUNC(doc.toString())) {
      log.log(Level.FINEST, "Using a UNC path.");
      return getUncShareAclView(doc.toString());
    } else if (Shlwapi.INSTANCE.PathIsNetworkPath(doc.toString())) {
      log.log(Level.FINEST, "Using a mapped drive.");
      // Call WNetGetUniversalNameW with the size needed for 
      // UNIVERSAL_NAME_INFO. If WNetGetUniversalNameW returns ERROR_MORE_DATA
      // that indicates that a larger buffer is needed. If this happens, make
      // a second call to WNetGetUniversalNameW with a buffer big enough.
      Mpr mprlib = Mpr.INSTANCE;
      Memory buf = new Memory(1024);
      IntByReference bufSize = new IntByReference((int)buf.size());
      int result = mprlib.WNetGetUniversalNameW(doc.getRoot().toString(),
          Mpr.UNIVERSAL_NAME_INFO_LEVEL, buf, bufSize);
      if (result == WinNT.ERROR_MORE_DATA) {
        buf = new Memory(bufSize.getValue());
        result = Mpr.INSTANCE.WNetGetUniversalNameW(doc.getRoot().toString(),
            Mpr.UNIVERSAL_NAME_INFO_LEVEL, buf, bufSize);
      }
      if (result != WinNT.NO_ERROR) {
        throw new IOException("Unable to get UNC path for the mapped path " +
            doc + ". Result: " + result);
      }

      Mpr.UNIVERSAL_NAME_INFO info = new Mpr.UNIVERSAL_NAME_INFO(buf);
      return getUncShareAclView(info.lpUniversalName);
    } else {
      log.log(Level.FINEST, "Using a local drive.");
      return new WindowsAclFileAttributeView(Collections.<AclEntry>emptyList());
    }
    // TODO(mifern): For a local drive, mapped and UNC the share Acl must also
    // include the Acls from the config point to the root.
  }

  private AclFileAttributeView getUncShareAclView(String uncPath)
      throws IOException {
    Matcher match = UNC_PATTERN.matcher(uncPath);
    if (!match.find()) {
      throw new IOException("The UNC path " + uncPath + " is not valid. "
          + "A UNC path of the form \\\\<host>\\<share> is required.");
    }
    String host = match.group(1);
    String share = match.group(2);
    log.log(Level.FINEST, "UNC: host: {0}, share: {1}.",
        new Object[] { host, share });
    return getShareAclView(host, share);
  }
  
  private AclFileAttributeView getShareAclView(String host, String share)
      throws IOException {
    Netapi32Ex netapi32 = Netapi32Ex.INSTANCE;
    PointerByReference buf = new PointerByReference();
    
    // Call NetShareGetInfo with a 502 to get the security descriptor of the
    // share. The security descriptor contains the Acl details for the share
    // that the adaptor needs.
    int result = netapi32.NetShareGetInfo(host, share, 502, buf);
    if (result != WinError.ERROR_SUCCESS) {
      if (result == WinError.ERROR_ACCESS_DENIED) {
        throw new IOException(
            "The user does not have access to the share Acl information.");
      } else if (result == WinError.ERROR_INVALID_LEVEL) {
        throw new IOException(
            "The value specified for the level parameter is not valid.");
      } else if (result == WinError.ERROR_INVALID_PARAMETER) {
        throw new IOException("A specified parameter is not valid.");
      } else if (result == WinError.ERROR_NOT_ENOUGH_MEMORY) {
        throw new IOException("Insufficient memory is available.");
      } else if (result == LMErr.NERR_NetNameNotFound) {
        throw new IOException("The share name does not exist.");
      } else {
        throw new IOException("Unable to the read share Acl. Error: " +
            result);
      }
    }

    Netapi32Ex.SHARE_INFO_502 info =
        new Netapi32Ex.SHARE_INFO_502(buf.getValue());
    netapi32.NetApiBufferFree(buf.getValue());

    SECURITY_DESCRIPTOR_RELATIVE sdr =
        new SECURITY_DESCRIPTOR_RELATIVE(info.shi502_security_descriptor);
    ACL dacl = sdr.getDiscretionaryACL();

    List<AclEntry> acl = new ArrayList<AclEntry>();
    for (ACCESS_ACEStructure ace : dacl.getACEStructures()) {
      AclEntry entry = newAclEntry(ace);
      if (entry != null) {
        acl.add(entry);
      }
    }

    return new WindowsAclFileAttributeView(acl);
  }

  /**
   * Creates an AclEntry from a ACCESS_ACEStructure.
   */
  private AclEntry newAclEntry(ACCESS_ACEStructure ace) {
    // Map the type.
    AclEntryType aclType = ACL_TYPE_MAP.get(ace.AceType);
    if (aclType == null) {
      log.log(Level.WARNING, "Unsupported access type: {0}.", ace.AceType);
      return null;
    }
    
    // Map the user.
    Account account = Advapi32Util.getAccountBySid(ace.getSID());
    if (account == null) {
      log.log(Level.WARNING, "Could not resolve the SID: {0}.",
          ace.getSidString());
      return null;
    }
    final String accountName = (account.domain == null ?
        account.name : account.domain + "\\" + account.name);
    UserPrincipal aclPrincipal;
    if (USER_SID_TYPES.contains(account.accountType)) {
      aclPrincipal = new User(accountName);
    } else if (GROUP_SID_TYPES.contains(account.accountType)) {
      aclPrincipal = new Group(accountName);
    } else {
      log.log(Level.WARNING,
          "Non supported account type {0}. Skipping account {1}.",
          new Object[] { account.accountType, accountName });
      return null;
    }
    
    // Map the permissions.
    Set<AclEntryPermission> aclPerms = new HashSet<AclEntryPermission>();
    for (Map.Entry<Integer, AclEntryPermission> e : ACL_PERMS_MAP.entrySet()) {
      if ((ace.Mask & e.getKey()) == e.getKey()) {
        aclPerms.add(e.getValue());
      }
    }
    
    // Map the flags.
    Set<AclEntryFlag> aclFlags = new HashSet<AclEntryFlag>();
    for (Map.Entry<Byte, AclEntryFlag> e : ACL_FLAGS_MAP.entrySet()) {
      if ((ace.Mask & e.getKey()) == e.getKey()) {
        aclFlags.add(e.getValue());
      }
    }

    AclEntry.Builder builder = AclEntry.newBuilder().setType(aclType)
        .setPrincipal(aclPrincipal);
    if (!aclFlags.isEmpty()) {
      builder.setFlags(aclFlags);
    }
    if (!aclPerms.isEmpty()) {
      builder.setPermissions(aclPerms);
    }
    return builder.build();
  }

  private class User implements UserPrincipal {
    private final String accountName;

    User(String accountName) {
      this.accountName = accountName;
    }

    @Override
    public String getName() {
      return accountName;
    }
  }

  private class Group implements GroupPrincipal {
    private final String accountName;

    Group(String accountName) {
      this.accountName = accountName;
    }

    @Override
    public String getName() {
      return accountName;
    }
  }

  private class WindowsAclFileAttributeView implements AclFileAttributeView {
    private final List<AclEntry> acl;

    WindowsAclFileAttributeView(List<AclEntry> acl) {
      this.acl = Collections.unmodifiableList(acl);
    }

    @Override
    public void setAcl(List<AclEntry> acl)
        throws UnsupportedOperationException {
      throw new UnsupportedOperationException("setAcl is not supported.");
    }

    @Override
    public List<AclEntry> getAcl() throws IOException {
      return acl;
    }

    @Override
    public String name() {
      return "acl";
    }

    @Override
    public UserPrincipal getOwner() throws UnsupportedOperationException {
      throw new UnsupportedOperationException("getOwner is not supported.");
    }

    @Override
    public void setOwner(UserPrincipal owner)
        throws UnsupportedOperationException {
      throw new UnsupportedOperationException("setOwner is not supported.");
    }
  }

  private interface Netapi32Ex extends Netapi32 {
    Netapi32Ex INSTANCE = (Netapi32Ex) Native.loadLibrary("Netapi32",
        Netapi32Ex.class, W32APIOptions.UNICODE_OPTIONS);

    public int NetShareGetInfo(String servername, String netname, int level,
        PointerByReference bufptr);

    /**
     * Documentation on SHARE_INFO_502 can be found at:
     * http://msdn.microsoft.com/en-us/library/windows/desktop/bb525410(v=vs.85).aspx
     */
    public static class SHARE_INFO_502 extends Structure {
      public String shi502_netname;
      public int shi502_type;
      public String shi502_remark;
      public int shi502_permissions;
      public int shi502_max_uses;
      public int shi502_current_uses;
      public String shi502_path;
      public String shi502_passwd;
      public int shi502_reserved;
      public Pointer shi502_security_descriptor;

      public SHARE_INFO_502() {
        super();
      }

      public SHARE_INFO_502(Pointer memory) {
        useMemory(memory);
        read();
      }
      
      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList(new String[] { 
            "shi502_netname", "shi502_type", "shi502_remark",
            "shi502_permissions", "shi502_max_uses", "shi502_current_uses",
            "shi502_path", "shi502_passwd", "shi502_reserved",
            "shi502_security_descriptor"
            });
      }
    }
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
      id = id.replaceFirst("//", "\\\\");
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

  private interface Shlwapi extends StdCallLibrary {
    Shlwapi INSTANCE = (Shlwapi) Native.loadLibrary("Shlwapi",
        Shlwapi.class, W32APIOptions.UNICODE_OPTIONS);

    boolean PathIsNetworkPath(String pszPath);
    boolean PathIsUNC(String pszPath);
  }

  private interface Mpr extends StdCallLibrary {
    Mpr INSTANCE = (Mpr) Native.loadLibrary("Mpr", Mpr.class,
        W32APIOptions.UNICODE_OPTIONS);

    public final int UNIVERSAL_NAME_INFO_LEVEL = 1;

    int WNetGetUniversalNameW(String lpLocalPath, int dwInfoLevel,
        Pointer lpBuffer, IntByReference lpBufferSize);

    public static class UNIVERSAL_NAME_INFO extends Structure {
      public String lpUniversalName;

      public UNIVERSAL_NAME_INFO() {
        super();
      }

      public UNIVERSAL_NAME_INFO(Pointer memory) {
        useMemory(memory);
        read();
      }

      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList(new String[] { "lpUniversalName" });
      }
    }
  }
  
  @Override
  public void destroy() {
    stopMonitorPath();
  }
}
