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

import com.google.common.base.Preconditions;

import com.google.enterprise.adaptor.fs.WinApi.Netapi32Ex;
import com.google.enterprise.adaptor.fs.WinApi.Shlwapi;
import com.google.enterprise.adaptor.fs.WindowsAclFileAttributeViews.Mpr;

import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Tests for {@link WindowsAclFileAttributeViews} */
public class WindowsAclFileAttributeViewsTest {

  private final WindowsAclFileAttributeViews wafav =
      new TestAclFileAttributeViews();

  private Path tempRoot;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    tempRoot = temp.getRoot().getCanonicalFile().toPath();
  }

  private Path newTempDir(String name) throws IOException {
    return temp.newFolder(name).toPath().toRealPath();
  }

  private Path newTempFile(String name) throws IOException {
    return temp.newFile(name).toPath().toRealPath();
  }

  private Path newTempFile(Path parent, String name) throws IOException {
    Preconditions.checkArgument(parent.startsWith(tempRoot));
    return Files.createFile(parent.resolve(name));
  }

  @Test
  public void testNewAclEntryUnsupportedAccessType() throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(new AccountSid())
        .setType(WinNT.SYSTEM_AUDIT_ACE_TYPE).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUnresolvableSid() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(new AccountSid()).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUnsupportedAccountType() throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(new AccountSid(SID_NAME_USE.SidTypeUnknown, "", "")).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUserPrincipal() throws Exception {
    testNewAclEntryUserPrincipal(AccountSid.user("userName", null), "userName");
  }

  @Test
  public void testNewAclEntryUserWithDomainPrincipal() throws Exception {
    testNewAclEntryUserPrincipal(AccountSid.user("userName", "domain"),
                                 "domain\\userName");
  }

  private void testNewAclEntryUserPrincipal(AccountSid account,
      String expectedName) throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder().setSid(account).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    UserPrincipal principal = aclEntry.principal();
    assertNotNull(principal);
    assertFalse(principal instanceof GroupPrincipal);
    assertEquals(expectedName, principal.getName());
  }

  @Test
  public void testNewAclEntryGroupPrincipal() throws Exception {
    testNewAclEntryGroupPrincipal(AccountSid.group("groupName", null),
                                  "groupName");
  }

  @Test
  public void testNewAclEntryGroupWithDomainPrincipal() throws Exception {
    testNewAclEntryGroupPrincipal(AccountSid.group("groupName", "domain"),
                                 "domain\\groupName");
  }

  @Test
  public void testNewAclEntryAliasPrincipal() throws Exception {
    AccountSid account =
        new AccountSid(SID_NAME_USE.SidTypeAlias, "alias", "domain");
    testNewAclEntryGroupPrincipal(account, "domain\\alias");
  }

  @Test
  public void testNewAclEntryWellKnownGroupPrincipal() throws Exception {
    AccountSid account =
        new AccountSid(SID_NAME_USE.SidTypeWellKnownGroup, "wellKnown", null);
    testNewAclEntryGroupPrincipal(account, "wellKnown");
  }

  private void testNewAclEntryGroupPrincipal(AccountSid account,
      String expectedName) throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder().setSid(account).build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    UserPrincipal principal = aclEntry.principal();
    assertNotNull(principal);
    assertTrue(principal instanceof GroupPrincipal);
    assertEquals(expectedName, principal.getName());
  }

  @Test
  public void testNewAclEntryIndividualPermissions() throws Exception {
    testNewAclEntryPermissions(WinNT.FILE_READ_DATA,
                               AclEntryPermission.READ_DATA);
    testNewAclEntryPermissions(WinNT.FILE_READ_ATTRIBUTES,
                               AclEntryPermission.READ_ATTRIBUTES);
    testNewAclEntryPermissions(WinNT.FILE_READ_EA,
                               AclEntryPermission.READ_NAMED_ATTRS);
    testNewAclEntryPermissions(WinNT.READ_CONTROL,
                               AclEntryPermission.READ_ACL);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_DATA,
                               AclEntryPermission.WRITE_DATA);
    testNewAclEntryPermissions(WinNT.FILE_APPEND_DATA,
                               AclEntryPermission.APPEND_DATA);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_ATTRIBUTES,
                               AclEntryPermission.WRITE_ATTRIBUTES);
    testNewAclEntryPermissions(WinNT.FILE_WRITE_EA,
                               AclEntryPermission.WRITE_NAMED_ATTRS);
    testNewAclEntryPermissions(WinNT.WRITE_DAC,
                               AclEntryPermission.WRITE_ACL);
    testNewAclEntryPermissions(WinNT.WRITE_OWNER,
                               AclEntryPermission.WRITE_OWNER);
    testNewAclEntryPermissions(WinNT.DELETE,
                               AclEntryPermission.DELETE);
    testNewAclEntryPermissions(WinNT.FILE_DELETE_CHILD,
                               AclEntryPermission.DELETE_CHILD);
    testNewAclEntryPermissions(WinNT.SYNCHRONIZE,
                               AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.FILE_EXECUTE,
                               AclEntryPermission.EXECUTE);
  }

  @Test
  public void testNewAclEntryFullPermissions() throws Exception {
    testNewAclEntryPermissions(WinNT.FILE_ALL_ACCESS,
                               AclEntryPermission.values());

  }

  @Test
  public void testNewAclEntryGenericPermissions() throws Exception {
    testNewAclEntryPermissions(WinNT.GENERIC_READ, AclEntryPermission.READ_DATA,
        AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS,
        AclEntryPermission.READ_ACL, AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.GENERIC_WRITE,
        AclEntryPermission.WRITE_DATA, AclEntryPermission.APPEND_DATA,
        AclEntryPermission.READ_ACL, AclEntryPermission.WRITE_ATTRIBUTES,
        AclEntryPermission.WRITE_NAMED_ATTRS, AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.GENERIC_EXECUTE,
        AclEntryPermission.EXECUTE, AclEntryPermission.READ_ATTRIBUTES,
        AclEntryPermission.READ_ACL, AclEntryPermission.SYNCHRONIZE);
    testNewAclEntryPermissions(WinNT.GENERIC_ALL, AclEntryPermission.values());
  }

  private void testNewAclEntryPermissions(int acePermissions,
      AclEntryPermission... expectedPermissions) throws Exception {
    Set<AclEntryPermission> expected =
        EnumSet.noneOf(AclEntryPermission.class);
    for (AclEntryPermission perm : expectedPermissions) {
      expected.add(perm);
    }
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(AccountSid.user("userName", null))
        .setPerms(acePermissions)
        .build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    assertEquals(expected, aclEntry.permissions());
  }

  @Test
  public void testNewAclEntryIndividualFlags() throws Exception {
    testNewAclEntryFlags(WinNT.OBJECT_INHERIT_ACE, AclEntryFlag.FILE_INHERIT);
    testNewAclEntryFlags(WinNT.INHERIT_ONLY_ACE, AclEntryFlag.INHERIT_ONLY);
    testNewAclEntryFlags(WinNT.CONTAINER_INHERIT_ACE,
                         AclEntryFlag.DIRECTORY_INHERIT);
    testNewAclEntryFlags(WinNT.NO_PROPAGATE_INHERIT_ACE,
                         AclEntryFlag.NO_PROPAGATE_INHERIT);
  }

  @Test
  public void testNewAclEntryMultipleFlags() throws Exception {
    testNewAclEntryFlags((byte) (WinNT.OBJECT_INHERIT_ACE |
        WinNT.CONTAINER_INHERIT_ACE | WinNT.INHERIT_ONLY_ACE |
        WinNT.NO_PROPAGATE_INHERIT_ACE), AclEntryFlag.values());
  }

  private void testNewAclEntryFlags(byte aceFlags,
      AclEntryFlag... expectedFlags) throws Exception {
    Set<AclEntryFlag> expected = EnumSet.noneOf(AclEntryFlag.class);
    for (AclEntryFlag flag : expectedFlags) {
      expected.add(flag);
    }
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(AccountSid.user("userName", null))
        .setFlags(aceFlags)
        .build();
    AclEntry aclEntry = wafav.newAclEntry(ace);
    assertNotNull(aclEntry);
    assertEquals(expected, aclEntry.flags());
  }

  @Test
  public void testGetAclViewsEmptyAcl() throws Exception {
    AclFileAttributeViews aclViews = getAclViews();
    assertNotNull(aclViews);
    assertTrue(aclViews.getDirectAclView().getAcl().isEmpty());
    assertTrue(aclViews.getInheritedAclView().getAcl().isEmpty());
  }

  @Test
  public void testGetAclViewsSingleDirectAce() throws Exception {
    AclFileAttributeView expected = new AclView(
        user("domain\\user").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(AccountSid.user("user", "domain"))
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build();
    AclFileAttributeViews aclViews = getAclViews(ace);
    assertNotNull(aclViews);
    assertTrue(aclViews.getInheritedAclView().getAcl().isEmpty());
    assertEquals(expected.getAcl(), aclViews.getDirectAclView().getAcl());
  }

  @Test
  public void testGetAclViewsSingleInheritedAce() throws Exception {
    AclFileAttributeView expected = new AclView(
        user("domain\\user").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(AccountSid.user("user", "domain"))
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE,
                  WinNT.INHERITED_ACE)
        .build();
    AclFileAttributeViews aclViews = getAclViews(ace);
    assertNotNull(aclViews);
    assertTrue(aclViews.getDirectAclView().getAcl().isEmpty());
    assertEquals(expected.getAcl(), aclViews.getInheritedAclView().getAcl());
  }

  @Test
  public void testGetAclViewsInheritedAndDirectAces() throws Exception {
    AclFileAttributeView expectedInherited = new AclView(
        group("Everyone").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclFileAttributeView expectedDirect = new AclView(
        user("BEDROCK\\Fred").type(ALLOW).perms(GENERIC_EXECUTE)
        .flags(FILE_INHERIT),
        user("BEDROCK\\Barney").type(DENY).perms(GENERIC_WRITE)
        .flags(DIRECTORY_INHERIT));
    AclFileAttributeViews aclViews = getAclViews(new AceBuilder()
        .setSid(AccountSid.user("Fred", "BEDROCK"))
        .setPerms(WinNT.GENERIC_EXECUTE)
        .setFlags(WinNT.OBJECT_INHERIT_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.group("Everyone", null))
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE,
                  WinNT.INHERITED_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.group("Administrators", null))
        .setPerms(WinNT.GENERIC_ALL)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE,
                  WinNT.INHERITED_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.user("Barney", "BEDROCK"))
        .setType(WinNT.ACCESS_DENIED_ACE_TYPE)
        .setPerms(WinNT.GENERIC_WRITE)
        .setFlags(WinNT.CONTAINER_INHERIT_ACE)
        .build());

    assertNotNull(aclViews);
    assertEquals(expectedDirect.getAcl(), aclViews.getDirectAclView().getAcl());
    assertEquals(expectedInherited.getAcl(),
                 aclViews.getInheritedAclView().getAcl());
  }

  private AclFileAttributeViews getAclViews(WinNT.ACCESS_ACEStructure... aces)
      throws Exception {
    final byte[] dacl = buildDaclMemory(aces);
    Kernel32 kernel32 = new UnsupportedKernel32() {
        @Override
        public int GetLastError() {
          // For when GetFileSecurity returns false.
          return W32Errors.ERROR_INSUFFICIENT_BUFFER;
        }
      };
    Advapi32 advapi32 = new UnsupportedAdvapi32() {
        @Override
        public boolean GetFileSecurity(WString lpFileName,
            int RequestedInformation, Pointer pointer, int nLength,
            IntByReference lpnLengthNeeded) {
          if (nLength < dacl.length) {
            lpnLengthNeeded.setValue(dacl.length);
            return false;
          } else {
            pointer.write(0, dacl, 0, nLength);
            return true;
          }
        }
      };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(advapi32, kernel32, null, null, null);
    return wafav.getAclViews(newTempFile("test"));
  }

  private byte[] buildDaclMemory(WinNT.ACCESS_ACEStructure... aces)
      throws Exception {
    WinNT.ACL acl = new WinNT.ACL();
    WinNT.SECURITY_DESCRIPTOR_RELATIVE securityDescriptor =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE();
    int totalSize = securityDescriptor.size() + acl.size();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      totalSize += ace.AceSize;
    }

    // Serialize the structures into a buffer.
    final byte[] buffer = new byte[totalSize];
    int offset = 0;
    // The start of the ACL follows the securityDescriptor in memory.
    securityDescriptor.Dacl = securityDescriptor.size();
    securityDescriptor.write();
    securityDescriptor.getPointer().read(0, buffer, offset,
                                         securityDescriptor.size());
    offset += securityDescriptor.size();
    acl.AceCount = (short) aces.length;
    acl.write();
    acl.getPointer().read(0, buffer, offset, acl.size());
    offset += acl.size();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      ace.write();
      ace.getPointer().read(0, buffer, offset, ace.AceSize);
      offset += ace.AceSize;
    }
    return buffer;
  }

  /**
   * Test the first IOException that can be thrown out of getFileSecurity().
   * In that method, the first call to advapi32.GetFileSecurity() is
   * expected to return W32Errors.ERROR_INSUFFICIENT_BUFFER and the
   * required buffer size.  This test returns a different error, which
   * gets rethrown as an IOException.
   */
  @Test
  public void testGetAclViewsException1() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    thrown.expect(IOException.class);
    testGetAclViewsException(W32Errors.ERROR_MORE_DATA);
  }

  /**
   * Test the second IOException that can be thrown out of getFileSecurity().
   * In that method, the second call to advapi32.GetFileSecurity() is
   * not expected to return any error.  This test returns an error on both
   * calls - the expected error for the first call and that same error for the
   * second call.
   */
  @Test
  public void testGetAclViewsException2() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    thrown.expect(IOException.class);
    testGetAclViewsException(W32Errors.ERROR_INSUFFICIENT_BUFFER);
  }

  private void testGetAclViewsException(final int errorCode) throws Exception {
    Kernel32 kernel32 = new UnsupportedKernel32() {
        @Override
        public int GetLastError() {
          return errorCode;
        }
      };
    Advapi32 advapi32 = new UnsupportedAdvapi32() {
        @Override
        public boolean GetFileSecurity(WString lpFileName,
            int RequestedInformation, Pointer pointer, int nLength,
            IntByReference lpnLengthNeeded) {
          lpnLengthNeeded.setValue(10);
          return false;
        }
      };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(advapi32, kernel32, null, null, null);
    wafav.getAclViews(newTempFile("test"));
  }

  @Test
  public void testGetShareAclViewLocalDrive() throws Exception {
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return false;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return false;
        }
      };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, null, shlwapi);
    AclFileAttributeView aclView = wafav.getShareAclView(newTempDir("test"));
    assertNotNull(aclView);
    assertTrue(aclView.getAcl().isEmpty());
  }

  @Test
  public void testGetShareAclViewUncPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return false;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return true;
        }
      };
    Path share = Paths.get("\\\\server\\share");
    testGetShareAclView(share, shlwapi, null);
  }

  @Test
  public void testGetShareAclViewBadUncPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return false;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return true;
        }
      };
    thrown.expect(IOException.class);
    testGetShareAclView(newTempDir("test"), shlwapi, null);
  }


  @Test
  public void testGetShareAclViewNetworkPath() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return true;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return false;
        }
      };
    Mpr mpr = new Mpr() {
        @Override
        public int WNetGetUniversalNameW(String lpLocalPath, int dwInfoLevel,
            Pointer lpBuffer, IntByReference lpBufferSize) {
          Mpr.UNIVERSAL_NAME_INFO info = new Mpr.UNIVERSAL_NAME_INFO();
          info.lpUniversalName = "\\\\server\\share";
          info.write();
          // Force a reallocation, even though we do not need it.
          if (lpBufferSize.getValue() != info.size()) {
            lpBufferSize.setValue(info.size());
            return WinNT.ERROR_MORE_DATA;
          }
          byte[] buf = new byte[info.size()];
          info.getPointer().read(0, buf, 0, buf.length);
          lpBuffer.write(0, buf, 0, buf.length);
          return WinNT.NO_ERROR;
        }
      };
    testGetShareAclView(newTempDir("test"), shlwapi, mpr);
  }

  @Test
  public void testGetShareAclViewNetworkPathFailure() throws Exception {
    TestHelper.assumeOsIsWindows();
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return true;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return false;
        }
      };
    Mpr mpr = new Mpr() {
        @Override
        public int WNetGetUniversalNameW(String lpLocalPath, int dwInfoLevel,
            Pointer lpBuffer, IntByReference lpBufferSize) {
          return WinNT.ERROR_INVALID_PARAMETER;
        }
      };
    thrown.expect(IOException.class);
    testGetShareAclView(newTempDir("test"), shlwapi, mpr);
  }

  private void testGetShareAclView(Path share, Shlwapi shlwapi, Mpr mpr)
      throws Exception {
    AclFileAttributeView expectedAcl = new AclView(
        group("Everyone").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    byte[] dacl = buildDaclMemory(
        new AceBuilder()
        .setSid(AccountSid.group("Everyone", null))
        .setPerms(WinNT.GENERIC_READ)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build(),
        new AceBuilder()
        .setSid(AccountSid.group("Administrators", null))
        .setPerms(WinNT.GENERIC_ALL)
        .setFlags(WinNT.OBJECT_INHERIT_ACE, WinNT.CONTAINER_INHERIT_ACE)
        .build());

    Memory memory = new Memory(dacl.length);
    memory.write(0, dacl, 0, dacl.length);
    final Netapi32Ex.SHARE_INFO_502 info = new Netapi32Ex.SHARE_INFO_502();
    info.shi502_security_descriptor = memory;
    info.write();

    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetShareGetInfo(String serverName, String netName, int level,
            PointerByReference bufptr) {
          bufptr.setValue(info.getPointer());
          return WinError.ERROR_SUCCESS;
        }
        @Override
        public int NetApiBufferFree(Pointer buf) {
          return WinError.ERROR_SUCCESS;
        }
      };

    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, mpr, netapi, shlwapi);

    AclFileAttributeView aclView = wafav.getShareAclView(share);
    assertNotNull(aclView);
    assertEquals(expectedAcl.getAcl(), aclView.getAcl());
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureAccessDenied()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(WinError.ERROR_ACCESS_DENIED);
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureInvalidLevel()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(WinError.ERROR_INVALID_LEVEL);
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureInvalidParameter()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(WinError.ERROR_INVALID_PARAMETER);
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureInsufficientMemory()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(WinError.ERROR_NOT_ENOUGH_MEMORY);
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureNetNameNotFound()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(LMErr.NERR_NetNameNotFound);
  }

  @Test
  public void testGetShareAclViewNetSareGetInfoFailureOther()
      throws Exception {
    TestHelper.assumeOsIsWindows();
    testGetShareAclViewNetSareGetInfoFailure(WinError.ERROR_NOT_READY);
  }

  private void testGetShareAclViewNetSareGetInfoFailure(final int error)
      throws Exception {
    Shlwapi shlwapi = new Shlwapi() {
        @Override
        public boolean PathIsNetworkPath(String pszPath) {
          return false;
        }
        @Override
        public boolean PathIsUNC(String pszPath) {
          return true;
        }
      };
    Netapi32Ex netapi = new UnsupportedNetapi32() {
        @Override
        public int NetShareGetInfo(String serverName, String netName, int level,
            PointerByReference bufptr) {
          return error;
        }
        @Override
        public int NetApiBufferFree(Pointer buf) {
          return WinError.ERROR_SUCCESS;
        }
      };
    WindowsAclFileAttributeViews wafav =
        new TestAclFileAttributeViews(null, null, null, netapi, shlwapi);
    Path share = Paths.get("\\\\server\\share");

    thrown.expect(IOException.class);
    AclFileAttributeView aclView = wafav.getShareAclView(share);
  }

  static class AceBuilder {
    private byte type;
    private byte flags;
    private int perms;
    private AccountSid sid;

    public AceBuilder setType(byte type) {
      this.type = type;
      return this;
    }

    public AceBuilder setFlags(byte... flags) {
      for (byte flag : flags) {
        this.flags |= flag;
      }
      return this;
    }

    public AceBuilder setPerms(int... perms) {
      for (int perm : perms) {
        this.perms |= perm;
      }
      return this;
    }

    public AceBuilder setSid(AccountSid sid) {
      this.sid = sid;
      return this;
    }

    public WinNT.ACCESS_ACEStructure build() {
      // Because ACCESS_ACEStructure does not allow me to set the SID
      // directly, I must create a serialized ACE containing a Pointer
      // to my AccountSid, then create a new ACE from that memory.
      WinNT.ACCESS_ACEStructure ace = new Ace();
      ace.AceType = type;
      ace.AceFlags = flags;
      ace.Mask = perms;
      ace.AceSize = (short)(ace.size() + Pointer.SIZE);
      ace.write();
      byte[] buffer = new byte[ace.AceSize];
      ace.getPointer().read(0, buffer, 0, ace.size());
      Memory memory = new Memory(buffer.length);
      memory.write(0, buffer, 0, ace.size());
      sid.write();
      // See ACCESS_ACEStructure(Pointer p) constructor for mystery offsets.
      memory.setPointer(4 + 4, sid.getPointer());
      ace = new Ace(memory);
      assertEquals(ace.getSID().sid, sid.getPointer());
      return ace;
    }
  }

  static class Ace extends WinNT.ACCESS_ACEStructure {
    public Ace() {
    }

    public Ace(Pointer p) {
      super(p);
    }

    @Override
    public String getSidString() {
      return new AccountSid(getSID().sid).toString();
    }
  }

  public static class AccountSid extends Structure {

    public static AccountSid user(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeUser, name, domain);
    }

    public static AccountSid group(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeGroup, name, domain);
    }

    @Override
    protected List getFieldOrder() {
      return Arrays.asList(new String[] { "type", "name", "domain" });
    }

    public int type;
    public String name;
    public String domain;

    public AccountSid() {
    }

    public AccountSid(Pointer p) {
      super(p);
      read();
    }

    public AccountSid(int type, String name, String domain) {
      this.type = type;
      this.name = name;
      this.domain = domain;
    }

    public Account getAccount() throws Win32Exception {
      if (name == null && domain == null) {
        throw new Win32Exception(WinError.ERROR_NONE_MAPPED);
      } else {
        Account account = new Account();
        account.accountType = type;
        account.name = name;
        account.domain = domain;
        return account;
      }
    }

    @Override
    public String toString() {
      if (name == null && domain == null) {
        return "null";
      } else {
        return (domain == null) ? name : domain + "\\" + name;
      }
    }
  }

  /**
   * An subclass of WindowsAclFileAttributeViews that avoids making
   * actual Windows API calls.
   */
  static class TestAclFileAttributeViews extends WindowsAclFileAttributeViews {
    public TestAclFileAttributeViews() {
      super(null, null, null, null, null);
    }

    public TestAclFileAttributeViews(Advapi32 advapi32, Kernel32 kernel32,
      Mpr mpr, Netapi32Ex netapi32, Shlwapi shlwapi) {
      super(advapi32, kernel32, mpr, netapi32, shlwapi);
    }

    @Override
    Account getAccountBySid(WinNT.PSID sid) throws Win32Exception {
      return new AccountSid(sid.sid).getAccount();
    }
  }
}
