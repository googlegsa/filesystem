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
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.UserPrincipal;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WindowsFileDelegate implements FileDelegate {
  private static final Logger log
      = Logger.getLogger(WindowsFileDelegate.class.getName());

  private Set<String> supportedWindowsAccounts;
  private String builtinPrefix;

  public WindowsFileDelegate(Set<String> supportedWindowsAccounts,
      String builtinPrefix) {
    Preconditions.checkNotNull(supportedWindowsAccounts,
        "supported Windows accounts may not be null");
    Preconditions.checkNotNull(builtinPrefix,
        "BUILTIN groups prefix may not be null");
    this.supportedWindowsAccounts = Collections.unmodifiableSet(
        new HashSet<String>(supportedWindowsAccounts));
    this.builtinPrefix = builtinPrefix.toUpperCase();
  }

  @Override
  public Acl getDirectAcl(Path doc, boolean isRoot) throws IOException {
    Set<GroupPrincipal> permitGroups = new HashSet<GroupPrincipal>();
    Set<GroupPrincipal> denyGroups = new HashSet<GroupPrincipal>();
    Set<UserPrincipal> permitUsers = new HashSet<UserPrincipal>();
    Set<UserPrincipal> denyUsers = new HashSet<UserPrincipal>();
    AclFileAttributeView aclAttributes = Files.getFileAttributeView(
        doc, AclFileAttributeView.class);
    for (AclEntry entry : aclAttributes.getAcl()) {
      if (entry.principal() instanceof
          java.nio.file.attribute.GroupPrincipal) {
        checkAndAddAclEntry(doc, entry, permitGroups, denyGroups,
            new PrincipalFactory<GroupPrincipal>() {
              public GroupPrincipal newInstance(String group) {
                return new GroupPrincipal(group);
              }
            });
      } else if (entry.principal() instanceof
          java.nio.file.attribute.UserPrincipal) {
        checkAndAddAclEntry(doc, entry, permitUsers, denyUsers,
            new PrincipalFactory<UserPrincipal>() {
              public UserPrincipal newInstance(String user) {
                return new UserPrincipal(user);
              }
            });
      }
    }

    Acl.Builder builder = new Acl.Builder()
        .setPermitGroups(permitGroups)
        .setDenyGroups(denyGroups)
        .setPermitUsers(permitUsers)
        .setDenyUsers(denyUsers);
    if (!isRoot) {
      builder.setInheritFrom(newDocId(doc.getParent()));
    }
    if (Files.isDirectory(doc)) {
      builder.setInheritanceType(InheritanceType.AND_BOTH_PERMIT);
    }

    // TODO(mifern): We have to take into account share Acls for the root.

    // TODO(mifern): setEverythingCaseInsensitive needs to called but
    // don't do it for now to work around a GSA bug.
    //builder.setEverythingCaseInsensitive();

    return builder.build();
  }

  @Override
  public DocId newDocId(Path doc) throws IOException {
    File docFile = doc.toFile().getCanonicalFile();
    String docId = docFile.getAbsolutePath().replace('\\', '/');
    if (docFile.isDirectory()) {
      if (!docId.endsWith("/")) {
        docId += "/";
      }
    }
    return new DocId(docId);
  }

  /**
   * Checks for various conditions on AclEntry's before adding them as valid
   * permit or deny entries.
   *
   * @param doc The file/folder that is being checked.
   * @param entry The AclEntry to checked and added.
   * @param permitSet Set where the principal is added if the entry is a
   * valid read permission.
   * @param denySet Set where the principal is added if the entry is a
   * deny read permission.
   * @param factory The factory used to create the object that is added
   * to permitSet or the denySet.
   */
  private <T extends Principal> void checkAndAddAclEntry(Path doc,
      AclEntry entry, Set<T> permitSet, Set<T> denySet,
      PrincipalFactory<T> factory) {
    String principalName = entry.principal().getName();

    if (!isSupportedWindowsAccount(principalName)) {
      if (isBuiltin(principalName)) {
        log.log(Level.FINEST, "Filtering BUILTIN ACE {0} for file {1}.",
            new Object[] { entry, doc });
        return;
      }
    }
    if (isSid(principalName)) {
      log.log(Level.FINEST, "Filtering unresolved ACE {0} for file {1}.",
          new Object[] { entry, doc });
      return;
    }
    if (!hasReadPermission(entry.permissions())) {
      log.log(Level.FINEST, "Filtering non-read ACE {0} for file {1}.",
          new Object[] { entry, doc });
      return;
    }

    if (entry.type() == AclEntryType.ALLOW) {
      log.log(Level.FINEST, "Adding permit ACE {0} for file {1}.",
          new Object[] { entry, doc });
      permitSet.add(factory.newInstance(principalName));
    } else if (entry.type() == AclEntryType.DENY) {
      log.log(Level.FINEST, "Adding deny read ACE {0} for file {1}.",
          new Object[] { entry, doc });
      denySet.add(factory.newInstance(principalName));
    }
  }

  /**
   * Returns true if the provided set of {@link AclEntryPermission} enables
   * read permission.
   */
  private boolean hasReadPermission(Set<AclEntryPermission> p) {
    return p.contains(AclEntryPermission.READ_DATA)
        && p.contains(AclEntryPermission.READ_ACL)
        && p.contains(AclEntryPermission.READ_ATTRIBUTES)
        && p.contains(AclEntryPermission.READ_NAMED_ATTRS);
  }

  /**
   * Returns true if the passed in user name is a Windows builtin user.
   */
  private boolean isBuiltin(String name) {
    return name.toUpperCase().startsWith(builtinPrefix);
  }

  /**
   * Returns true if the supplied account qualifies for inclusion in an ACL,
   * regardless of the value returned by {@link #isBuiltin(String name)}.
   */
  private final boolean isSupportedWindowsAccount(String user) {
    return supportedWindowsAccounts.contains(user);
  }

  /**
   * Returns true if the supplied account an unresolved SID.
   */
  private final boolean isSid(String user) {
    // TODO(mifern): Implementation needed. Can use JNA ConvertStringSidToSid.
    // If ConvertStringSidToSid return true then it's a SID.
    return false;
  }

  /**
   * PrincipalFactory is a factory used by checkAndAddAclEntry to create the
   * entries added to permitSet and denySet.
   */
  interface PrincipalFactory<T> {
    T newInstance(String user);
  }
}
