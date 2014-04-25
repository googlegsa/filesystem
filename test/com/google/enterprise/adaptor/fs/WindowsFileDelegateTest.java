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

import static com.google.enterprise.adaptor.fs.AclView.user;
import static com.google.enterprise.adaptor.fs.AclView.group;
import static com.google.enterprise.adaptor.fs.AclView.GenericPermission.*;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import static java.nio.file.attribute.AclEntryFlag.*;
import static java.nio.file.attribute.AclEntryPermission.*;
import static java.nio.file.attribute.AclEntryType.*;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.common.io.CharStreams;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.fs.WinApi.Netapi32Ex;

import org.junit.*;
import org.junit.rules.ExpectedException;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Collections;
import java.util.Set;

/** Tests for {@link WindowsFileDelegate} */
public class WindowsFileDelegateTest extends TestWindowsAclViews {

  @BeforeClass
  public static void checkIfRunningOnWindows() {
    TestHelper.assumeOsIsWindows();
  }

  private FileDelegate delegate = new WindowsFileDelegate();
  private AccumulatingAsyncDocIdPusher pusher =
      new AccumulatingAsyncDocIdPusher();
  private Path tempRoot;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Before
  public void setUp() throws Exception {
    tempRoot = getTempRoot();
  }

  @After
  public void tearDown() {
    delegate.destroy();
  }

  @Test
  public void testGetDfsShareAclView() throws Exception {
    // The *_OBJECT_ACE_TYPEs will get filtered out by newAclEntry().
    AclFileAttributeView expectedAcl = new AclView(
        group("AccessAllowedAce").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT),
        user("AccessDeniedAce").type(DENY).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));

    AclFileAttributeView aclView = getDfsShareAclView(
        new AceBuilder()
        .setSid(AccountSid.group("AccessAllowedAce", null))
        .setType(WinNT.ACCESS_ALLOWED_ACE_TYPE)
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.user("AccessAllowedObjectAce", null))
        .setType(WinNT.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
        .setPerms(WinNT.GENERIC_ALL)
        .setFlags(WinNT.OBJECT_INHERIT_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.user("AccessDeniedAce", null))
        .setType(WinNT.ACCESS_DENIED_ACE_TYPE)
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.group("AccessDeniedObjectAce", null))
        .setType(WinNT.ACCESS_DENIED_OBJECT_ACE_TYPE)
        .setPerms(WinNT.GENERIC_ALL)
        .setFlags(WinNT.OBJECT_INHERIT_ACE)
        .build());

    assertNotNull(aclView);
    assertEquals(expectedAcl.getAcl(), aclView.getAcl());
  }

  @Test
  public void testGetDfsShareAclViewUnsupportedAceType() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    AclFileAttributeView aclView = getDfsShareAclView(
        new AceBuilder()
        .setSid(AccountSid.group("SystemAuditAce", null))
        .setType(WinNT.SYSTEM_AUDIT_ACE_TYPE)
        .setPerms(WinNT.GENERIC_ALL)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build());
  }

  private static AclFileAttributeView getDfsShareAclView(
      WinNT.ACCESS_ACEStructure... aces) throws Exception {
    byte[] dacl = buildDaclMemory(aces);
    final Memory memory = new Memory(dacl.length);
    memory.write(0, dacl, 0, dacl.length);

    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetDfsGetSecurity(String dfsPath, int securityInfo,
            PointerByReference bufptr, IntByReference bufsz) {
          bufptr.setValue(memory);
          bufsz.setValue((int)(memory.size()));
          return WinError.ERROR_SUCCESS;
        }
        @Override
        public int NetApiBufferFree(Pointer buf) {
          return WinError.ERROR_SUCCESS;
        }
      };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, netapi, null);
    WindowsFileDelegate delegate = new WindowsFileDelegate(null, netapi, wafav);

    return delegate.getDfsShareAclView(Paths.get("\\\\host\\share"));
  }

  @Test
  public void testGetDfsShareAclViewError() throws Exception {
    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetDfsGetSecurity(String dfsPath, int securityInfo,
            PointerByReference bufptr, IntByReference bufsz) {
          return WinError.ERROR_ACCESS_DENIED;
        }
        @Override
        public int NetApiBufferFree(Pointer buf) {
          return WinError.ERROR_SUCCESS;
        }
      };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, netapi, null);
    WindowsFileDelegate delegate = new WindowsFileDelegate(null, netapi, wafav);

    thrown.expect(Win32Exception.class);
    delegate.getDfsShareAclView(Paths.get("\\\\host\\share"));
  }

  @Test
  public void testGetDfsUncActiveStorageUncError() throws Exception {
    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetDfsGetInfo(String dfsPath, String server, String share,
            int level, PointerByReference bufptr) {
          return WinError.ERROR_ACCESS_DENIED;
        }
      };
    assertNull(getDfsUncActiveStorageUnc(netapi));
  }

  @Test
  public void testGetDfsUncActiveStorageUncNoStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3();

    assertEquals(0, info.NumberOfStorages.intValue());
    thrown.expect(IOException.class);
    getDfsUncActiveStorageUnc(info);
  }

  @Test
  public void testGetDfsUncActiveStorageUncSingleActiveStorage()
      throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(
        new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "server", "share"));

    assertEquals(1, info.NumberOfStorages.intValue());
    assertEquals(Paths.get("\\\\server\\share"),
                 getDfsUncActiveStorageUnc(info));
  }

  @Test
  public void testGetDfsUncActiveStorageUncNoActiveStorage() throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(
        new Storage(0, "server", "share"));

    assertEquals(1, info.NumberOfStorages.intValue());
    thrown.expect(IOException.class);
    getDfsUncActiveStorageUnc(info);
  }

  @Test
  public void testGetDfsUncActiveStorageUncSomeActiveStorage()
      throws Exception {
    final Netapi32Ex.DFS_INFO_3 info = newDfsInfo3(
        new Storage(0, "inactive", "inactive"),
        new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "server", "share"),
        new Storage(Netapi32Ex.DFS_STORAGE_STATE_ONLINE, "active", "active"));

    assertEquals(3, info.NumberOfStorages.intValue());
    assertEquals(Paths.get("\\\\server\\share"),
                 getDfsUncActiveStorageUnc(info));
  }

  private static Path getDfsUncActiveStorageUnc(
      final Netapi32Ex.DFS_INFO_3 info) throws Exception {
    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetDfsGetInfo(String dfsPath, String server, String share,
            int level, PointerByReference bufptr) {
          bufptr.setValue(info.getPointer());
          return LMErr.NERR_Success;
        }
        @Override
        public int NetApiBufferFree(Pointer buf) {
          return WinError.ERROR_SUCCESS;
        }
      };

    return getDfsUncActiveStorageUnc(netapi);
  }

  private static Path getDfsUncActiveStorageUnc(Netapi32Ex netapi)
      throws Exception {
    WindowsFileDelegate delegate = new WindowsFileDelegate(null, netapi, null);
    Path dfsPath = Paths.get("\\\\host\\share");
    return delegate.getDfsUncActiveStorageUnc(dfsPath);
  }

  @Test
  public void testNewDocIdLocalFiles() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test");

    String id = delegate.newDocId(tempRoot).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.endsWith("/"));

    id = delegate.newDocId(dir).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.startsWith(dir.toString().replace('\\', '/')));
    assertTrue(id.endsWith("/"));

    id = delegate.newDocId(file).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.startsWith(dir.toString().replace('\\', '/')));
    assertTrue(id.equals(file.toString().replace('\\', '/')));
    assertFalse(id.endsWith("/"));
  }

  @Test
  public void testNewDocIdVirtualUncPaths() throws Exception {
    assertEquals("\\\\host/share",
        delegate.newDocId(Paths.get("\\\\host\\share")).getUniqueId());
    assertEquals("\\\\host/share",
        delegate.newDocId(Paths.get("\\\\host\\share\\")).getUniqueId());
    assertEquals("\\\\host/share/foo/bar",
        delegate.newDocId(Paths.get("\\\\host\\share\\foo\\bar"))
        .getUniqueId());
  }

  @Test
  public void testNewDocIdLocalUncPaths() throws Exception {
    String uncTempRoot = getTempRootAsUncPath();
    assumeNotNull(uncTempRoot);
    Path tempRoot = Paths.get(uncTempRoot);
    String expectedTempRootId = "\\\\" + uncTempRoot.substring(2)
        .replace('\\', '/') + "/";

    assertEquals(expectedTempRootId,
        delegate.newDocId(tempRoot).getUniqueId());

    newTempDir("testDir");
    assertEquals(expectedTempRootId + "testDir/",
        delegate.newDocId(tempRoot.resolve("testDir")).getUniqueId());

    newTempFile("test");
    assertEquals(expectedTempRootId + "test",
        delegate.newDocId(tempRoot.resolve("test")).getUniqueId());
  }

  private String getTempRootAsUncPath() throws IOException {
    String tempPath = temp.getRoot().getCanonicalPath();
    if (tempPath.length() > 2 && tempPath.charAt(1) == ':') {
      String uncPath = "\\\\localhost\\" + tempPath.substring(0, 1) + "$"
          + tempPath.substring(2);
      try {
        // Now verify we have access to the local administrative share.
        if (new File(uncPath).list() != null) {
          return uncPath;
        }
      } catch (SecurityException e) {
        // Cannot access local administrative share.
      }
    }
    return null;
  }

  @Test
  public void testStartMonitorBadPath() throws Exception {
    Path file = newTempFile("test.txt");
    thrown.expect(IOException.class);
    delegate.startMonitorPath(file, pusher);
  }

  @Test
  public void testStartStopMonitor() throws Exception {
    delegate.startMonitorPath(tempRoot, pusher);
    delegate.stopMonitorPath();
  }

  @Test
  public void testMonitorAddFile() throws Exception {
    // These shouldn't show up as new or modified.
    newTempDir("existingDir");
    newTempFile("existingFile");
    delegate.startMonitorPath(tempRoot, pusher);
    Path file = newTempFile("test.txt");
    // Adding a file shows up as a change to its parent.
    checkForChanges(Collections.singleton(newRecord(tempRoot)));
  }

  @Test
  public void testMonitorDeleteFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, pusher);
    Files.delete(file);
    // Deleting a file shows up as a change to itself and its parent.
    checkForChanges(Sets.newHashSet(newRecord(tempRoot), newRecord(file)));
  }

  @Test
  public void testMonitorRenameFile() throws Exception {
    Path file = newTempFile("test.txt");
    Path newFile = file.resolveSibling("newName.txt");
    delegate.startMonitorPath(tempRoot, pusher);
    Files.move(file, newFile, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a file shows up as a change to its old name, its new name,
    // and its parent.
    checkForChanges(Sets.newHashSet(newRecord(tempRoot), newRecord(file),
        newRecord(newFile)));
  }

  @Test
  public void testMonitorMoveAccrossDirs() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path file1 = newTempFile(dir1, "test.txt");
    Path file2 = dir2.resolve(file1.getFileName());
    delegate.startMonitorPath(tempRoot, pusher);
    Files.move(file1, file2);
    // Moving a file shows up as a change to its old name, its new name,
    // its old parent, and its new parent.
    checkForChanges(Sets.newHashSet(newRecord(file1), newRecord(file2),
        newRecord(dir1), newRecord(dir2)));
  }

  @Test
  public void testMonitorModifyFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, pusher);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(newRecord(file)));
  }

  @Test
  public void testMonitorModifyFileAttributes() throws Exception {
    Path file = newTempFile("test.txt");
    FileTime lastModified = Files.getLastModifiedTime(file);
    delegate.startMonitorPath(tempRoot, pusher);
    Files.setLastModifiedTime(file, 
        FileTime.fromMillis(lastModified.toMillis() + 10000L));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(newRecord(file)));
  }

  @Test
  public void testMonitorRenameDir() throws Exception {
    Path dir = newTempDir("dir1");
    Path newDir = dir.resolveSibling("newName.dir");
    delegate.startMonitorPath(tempRoot, pusher);
    Files.move(dir, newDir, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a directory shows up as a change to its old name, its new name,
    // and its parent.
    checkForChanges(Sets.newHashSet(newRecord(tempRoot), newRecord(dir)));
  }

  @Test
  public void testMonitorMoveDir() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path dir1dir2 = dir1.resolve(dir2.getFileName());
    delegate.startMonitorPath(tempRoot, pusher);
    Files.move(dir2, dir1dir2);
    // Moving a file shows up as a change to its old name, its new name,
    // its old parent, and its new parent.
    checkForChanges(Sets.newHashSet(newRecord(tempRoot), newRecord(dir1),
        newRecord(dir2)));
  }

  @Test
  public void testMonitorChangesInSubDirs() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test.txt");
    delegate.startMonitorPath(tempRoot, pusher);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Sets.newHashSet(newRecord(file), newRecord(dir)));
  }

  private void checkForChanges(Set<DocIdPusher.Record> expected)
      throws Exception {
    // Collect up the changes.
    Set<DocIdPusher.Record> changes = Sets.newHashSet();
    final long maxLatencyMillis = 10000;
    long latencyMillis = maxLatencyMillis;
    long batchLatencyMillis = 500;
    boolean inFollowup = false;

    while (latencyMillis > 0) {
      Thread.sleep(batchLatencyMillis);
      latencyMillis -= batchLatencyMillis;

      changes.addAll(pusher.getRecords());
      pusher.reset();
      if (changes.size() == expected.size()) {
        // If the changes size is equal to the expected size then
        // keep listening for changes for the same period of time
        // that it took to get the current notifications to see if
        // we find any additional changes.
        if (!inFollowup) {
          latencyMillis = maxLatencyMillis - latencyMillis;
          inFollowup = true;
        }
      }
      if (changes.size() > expected.size()) {
        // We've found more changes than are expected. Just stop
        // listening, we'll fail below.
        break;
      }
    }

    // Now verify that the changes we got were the ones that were expected.
    assertEquals(expected, changes);
  }

  private DocIdPusher.Record newRecord(Path path) throws Exception {
    return new DocIdPusher.Record.Builder(delegate.newDocId(path))
        .setCrawlImmediately(true).build();
  }

  private static Netapi32Ex.DFS_INFO_3 newDfsInfo3(Storage... storages) {
    final int sizeOfInfo = new Netapi32Ex.DFS_STORAGE_INFO().size();
    final int numberOfStorages = storages.length;

    // Cannot supply length of 0 so always allocate 1 more byte than needed.
    Memory storagesMem = new Memory(1 + numberOfStorages * sizeOfInfo);
    int offset = 0;
    for (Storage storage : storages) {
      storagesMem.setLong(offset, storage.state);
      offset += Native.LONG_SIZE;
      writeWString(storagesMem, offset, storage.serverName);
      offset += Pointer.SIZE;
      writeWString(storagesMem, offset, storage.shareName);
      offset += Pointer.SIZE;
    }

    Memory ptr = new Memory(40);
    writeWString(ptr, 0, new WString(""));
    writeWString(ptr, Pointer.SIZE, new WString(""));
    ptr.setLong(2 * Pointer.SIZE, 0);
    ptr.setLong(2 * Pointer.SIZE + Native.LONG_SIZE, numberOfStorages);
    ptr.setPointer(2 * Pointer.SIZE + 2 * Native.LONG_SIZE, storagesMem);
    return new Netapi32Ex.DFS_INFO_3(ptr);
  }

  private static void writeWString(Memory m, int offset, WString str) {
    int len = (str.length() + 1) * Native.WCHAR_SIZE;
    Memory ptr = new Memory(len);
    ptr.setString(0, str);
    m.setPointer(offset, ptr);
  }

  static class Storage {
    protected final int state;
    protected final WString serverName;
    protected final WString shareName;

    public Storage(int state, String serverName, String shareName) {
      this.state = state;
      this.serverName = new WString(serverName);
      this.shareName = new WString(shareName);
    }
  }
}
