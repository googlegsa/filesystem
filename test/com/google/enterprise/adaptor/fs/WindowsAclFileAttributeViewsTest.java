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

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import org.junit.*;
import org.junit.rules.ExpectedException;

import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;

import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Set;

/** Tests for {@link WindowsAclFileAttributeViews} */
public class WindowsAclFileAttributeViewsTest {

  private final WindowsAclFileAttributeViews wafav =
      new TestAclFileAttributeViews();

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testNewAclEntryUnsupportedAccessType() throws Exception {
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setType(WinNT.SYSTEM_AUDIT_ACE_TYPE).build();
    assertNull(wafav.newAclEntry(ace));
  }

  @Test
  public void testNewAclEntryUnresolvableSid() throws Exception {
    TestHelper.assumeOsIsWindows(); // For new Win32Exception().
    WinNT.ACCESS_ACEStructure ace = new AceBuilder()
        .setSid(new AccountSid(null)).build();
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

  static class AceBuilder {
    private Ace ace = new Ace();

    public AceBuilder setType(byte type) {
      ace.AceType = type;
      return this;
    }

    public AceBuilder setFlags(byte... flags) {
      for (byte flag : flags) {
        ace.AceFlags |= flag;
      }
      return this;
    }

    public AceBuilder setPerms(int... perms) {
      for (int perm : perms) {
        ace.Mask |= perm;
      }
      return this;
    }

    public AceBuilder setSid(WinNT.PSID sid) {
      ace.setSID(sid);
      return this;
    }

    public WinNT.ACCESS_ACEStructure build() {
      return ace;
    }
  }

  static class Ace extends WinNT.ACCESS_ACEStructure {
    // psid is not publicly settable in ACCESS_ACEStructure.
    private WinNT.PSID sid;

    public void setSID(WinNT.PSID sid) {
      this.sid = sid;
    }

    @Override
    public WinNT.PSID getSID() {
      return (sid != null) ? sid : super.getSID();
    }

    @Override
    public String getSidString() {
      return (sid != null) ? sid.toString() : super.getSidString();
    }
  }

  /** A SID implemention that wraps an Account, avoiding AD lookup. */
  static class AccountSid extends WinNT.PSID {
    private final Account account;

    public static AccountSid user(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeUser, name, domain);
    }

    public static AccountSid group(String name, String domain) {
      return new AccountSid(SID_NAME_USE.SidTypeGroup, name, domain);
    }

    public AccountSid(Account account) {
      this.account = account;
    }

    public AccountSid(int type, String name, String domain) {
      account = new Account();
      account.accountType = type;
      account.name = name;
      account.domain = domain;
    }

    public Account getAccount() throws Win32Exception {
      if (account == null) {
        throw new Win32Exception(WinError.ERROR_NONE_MAPPED);
      }
      return account;
    }

    @Override
    public String toString() {
      if (account == null) {
        return "null";
      } else {
        return (account.domain == null) ? account.name
            : account.domain + "\\" + account.name;
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

    @Override
    Account getAccountBySid(WinNT.PSID sid) throws Win32Exception {
      if (sid instanceof AccountSid) {
        return ((AccountSid) sid).getAccount();
      } else {
        return super.getAccountBySid(sid);
      }
    }
  }
}
