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

import static com.google.enterprise.adaptor.fs.AclView.user;
import static com.google.enterprise.adaptor.fs.AclView.group;
import static com.google.enterprise.adaptor.fs.AclView.GenericPermission.*;

import static org.junit.Assert.*;

import static java.nio.file.attribute.AclEntryFlag.*;
import static java.nio.file.attribute.AclEntryPermission.*;
import static java.nio.file.attribute.AclEntryType.*;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.UserPrincipal;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.ArrayList;
import java.util.Set;

/**
 * Test cases for {@link AclBuilder}.
 */
public class AclBuilderTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();
  
  private final Path doc = Paths.get("foo", "bar");
  private final Set<String> windowsAccounts = ImmutableSet.of(
      "BUILTIN\\Administrators", "Everyone", "BUILTIN\\Users",
      "BUILTIN\\Guest", "NT AUTHORITY\\INTERACTIVE",
      "NT AUTHORITY\\Authenticated Users");
  private final String builtinPrefix = "BUILTIN\\";
  private final String namespace = "namespace";
  private final Set<GroupPrincipal> emptyGroups = ImmutableSet.of();
  private final AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mary").type(ALLOW).perms(GENERIC_READ, GENERIC_WRITE)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mike").type(DENY).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("EVERYONE").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("sales").type(DENY).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT));
  // This is the expected ACL for the above aclView.
  private final Acl expectedAcl = expectedBuilder().build();

  @Test
  public void testConstructorNullPath() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(null, aclView, windowsAccounts, builtinPrefix, namespace);
  }

  @Test
  public void testConstructorNullAclView() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, null, windowsAccounts, builtinPrefix, namespace);
  }

  @Test
  public void testConstructorNullAccounts() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, aclView, null, builtinPrefix, namespace);
  }

  @Test
  public void testConstructorNullPrefix() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, aclView, windowsAccounts, null, namespace);
  }

  @Test
  public void testConstructorNullNamespace() throws Exception {
    thrown.expect(NullPointerException.class);
    new AclBuilder(doc, aclView, windowsAccounts, builtinPrefix, null);
  }

  @Test
  public void testGetAcl() throws Exception {
    assertEquals(expectedAcl, newBuilder(aclView).getAcl().build());
  }

  @Test
  public void testGetInheritableByAllDescendentFoldersAcl() throws Exception {
    assertEquals(expectedAcl,
        newBuilder(aclView).getInheritableByAllDescendentFoldersAcl().build());
  }
  
  @Test
  public void testGetInheritableByAllDescendentFilesAcl() throws Exception {
    assertEquals(expectedAcl,
        newBuilder(aclView).getInheritableByAllDescendentFilesAcl().build());
  }
  
  @Test
  public void testGetInheritableByChildFoldersOnlyAcl() throws Exception {
    assertEquals(expectedAcl,
        newBuilder(aclView).getInheritableByChildFoldersOnlyAcl().build());
  }
  
  @Test
  public void testGetInheritableByChildFilesOnlyAcl() throws Exception {
    assertEquals(expectedAcl,
        newBuilder(aclView).getInheritableByChildFilesOnlyAcl().build());
  }

  @Test
  public void testFileInheritAcl() throws Exception {
    // "mary" and "sales" are only inheritable by files, not directories.
    AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mary").type(ALLOW).perms(GENERIC_READ, GENERIC_WRITE)
          .flags(FILE_INHERIT),
      user("mike").type(DENY).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("EVERYONE").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("sales").type(DENY).perms(GENERIC_READ)
          .flags(FILE_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The file inherit ACLs should have all the users and groups.
    assertEquals(expectedAcl,
        aclBuilder.getInheritableByAllDescendentFilesAcl().build());
    assertEquals(expectedAcl,
        aclBuilder.getInheritableByChildFilesOnlyAcl().build());

    // The folder inherit ACLs should not include "mary" or "sales".
    Acl expected = expectedBuilder()
        .setPermitUsers(users("joe")).setDenyGroups(emptyGroups).build();
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
  }

  @Test
  public void testFolderInheritAcl() throws Exception {
    // "mary" and "sales" are only inheritable by directories, not files.
    AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mary").type(ALLOW).perms(GENERIC_READ, GENERIC_WRITE)
          .flags(DIRECTORY_INHERIT),
      user("mike").type(DENY).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("EVERYONE").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      group("sales").type(DENY).perms(GENERIC_READ)
          .flags(DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The folder inherit ACLs should have all the users and groups.
    assertEquals(expectedAcl,
        aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expectedAcl,
        aclBuilder.getInheritableByChildFoldersOnlyAcl().build());

    // The file inherit ACLs should not include "mary" or "sales".
    Acl expected = expectedBuilder()
        .setPermitUsers(users("joe")).setDenyGroups(emptyGroups).build();
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFilesAcl().build());
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testNoPropagateFolderInheritAcl() throws Exception {
    AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mike").type(ALLOW).perms(GENERIC_READ)
          .flags(DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
      user("mary").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    Acl acl = aclBuilder.getInheritableByAllDescendentFoldersAcl().build();
    Acl expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mary")).build();
    assertEquals(expected, acl);

    acl = aclBuilder.getInheritableByChildFoldersOnlyAcl().build();
    expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mike", "mary")).build();
    assertEquals(expected, acl);
  }

  @Test
  public void testNoPropagateFileInheritAcl() throws Exception {
    AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mike").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, NO_PROPAGATE_INHERIT),
      user("mary").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    Acl acl = aclBuilder.getInheritableByAllDescendentFilesAcl().build();
    Acl expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mary")).build();
    assertEquals(expected, acl);

    acl = aclBuilder.getInheritableByChildFilesOnlyAcl().build();
    expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mike", "mary")).build();
    assertEquals(expected, acl);
  }

  @Test
  public void testInheritOnlyAcl() throws Exception {
    AclFileAttributeView aclView = new AclView(
      user("joe").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT),
      user("mike").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
      user("mary").type(ALLOW).perms(GENERIC_READ)
          .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // This node's ACL should not include mike.
    Acl expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mary")).build();
    assertEquals(expected, aclBuilder.getAcl().build());
                         
    // However, all of its children should include mike.
    expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mike", "mary")).build();
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testInsufficientReadPerms() throws Exception {
    AclFileAttributeView aclView = new AclView(
        user("joe").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT),
        user("mike").type(ALLOW).perms(READ_DATA)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    AclBuilder aclBuilder = newBuilder(aclView);

    // This node's ACLs should not include mike.
    Acl expected = emptyExpectedBuilder()
        .setPermitUsers(users("joe")).build();
    assertEquals(expected, aclBuilder.getAcl().build());
    assertEquals(expected, 
        aclBuilder.getInheritableByAllDescendentFoldersAcl().build());
    assertEquals(expected,
        aclBuilder.getInheritableByAllDescendentFilesAcl().build());
  }

  @Test
  public void testWindowsBuiltinUsers() throws Exception {
    ArrayList<AclEntry> entries = Lists.newArrayList();
    // Add all the permitted builtin users.
    for (String builtin : windowsAccounts) {
      entries.add(user(builtin).type(ALLOW).perms(GENERIC_READ)
                  .flags(FILE_INHERIT, DIRECTORY_INHERIT).build());
    }
    String badBuiltin = builtinPrefix + "BACKUP";
    // Now add a builtin user that should be excluded.
    entries.add(user(badBuiltin).type(ALLOW).perms(GENERIC_READ)
                .flags(FILE_INHERIT, DIRECTORY_INHERIT).build());

    AclFileAttributeView aclView =
        new AclView(entries.toArray(new AclEntry[0]));
    AclBuilder aclBuilder = newBuilder(aclView);

    // The permitted users should contain all of the acceptable builtins.
    // But should not contain the bad builtin.
    Acl expected = emptyExpectedBuilder()
        .setPermitUsers(users(Iterables.toArray(windowsAccounts, String.class)))
        .build();
    assertEquals(expected, aclBuilder.getAcl().build());
  }

  /** Returns an AclBuilder for the AclFileAttributeView. */
  private AclBuilder newBuilder(AclFileAttributeView aclView) {
    return new AclBuilder(doc, aclView, windowsAccounts, builtinPrefix,
                          namespace);
  }

  /**
   * Returns an Acl.Builder representing the aclView field.
   * The caller is expected to overwrite any of thes presets,
   * then call build().
   */
  private Acl.Builder expectedBuilder() {
    return emptyExpectedBuilder()
        .setPermitUsers(users("joe", "mary")).setDenyUsers(users("mike"))
        .setPermitGroups(groups("EVERYONE")).setDenyGroups(groups("sales"));
  }

  /**
   * Returns an Acl.Builder with no users or groups.
   */
  private Acl.Builder emptyExpectedBuilder() {
    return new Acl.Builder().setEverythingCaseInsensitive();
  }

  /**
   * Returns a Set of UserPrincipals of the named users.
   */
  private Set<UserPrincipal> users(String... users) {
    Set<UserPrincipal> principals = Sets.newHashSet();
    for (String user : users) {
      principals.add(new UserPrincipal(user, namespace));
    }
    return principals;
  }

  /**
   * Returns a Set of GroupPrincipals of the named groups.
   */
  private Set<GroupPrincipal> groups(String... groups) {
    Set<GroupPrincipal> principals = Sets.newHashSet();
    for (String group : groups) {
      principals.add(new GroupPrincipal(group, namespace));
    }
    return principals;
  }
}
