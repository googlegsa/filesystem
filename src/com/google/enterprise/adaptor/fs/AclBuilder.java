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
import com.google.common.base.Predicate;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.UserPrincipal;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Build Acl for the file system adaptor.
 */
public class AclBuilder {
  private static final Logger log 
      = Logger.getLogger(AclBuilder.class.getName());

  private Path doc;
  private AclFileAttributeView aclView;
  private Set<String> supportedWindowsAccounts;
  private String builtinPrefix;
  private String namespace;

  public AclBuilder(Path doc, AclFileAttributeView aclView,
      Set<String> supportedWindowsAccounts, String builtinPrefix,
      String namespace) {
    Preconditions.checkNotNull(doc, "doc may not be null");
    Preconditions.checkNotNull(aclView, "aclView may not be null");
    Preconditions.checkNotNull(supportedWindowsAccounts,
        "supportedWindowsAccounts may not be null");
    Preconditions.checkNotNull(builtinPrefix, "builtinPrefix may not be null");
    Preconditions.checkNotNull(namespace, "namespace may not be null");
    this.doc = doc;
    this.aclView = aclView;
    this.supportedWindowsAccounts = supportedWindowsAccounts;
    this.builtinPrefix = builtinPrefix.toUpperCase();
    this.namespace = namespace;
  }

  public Acl getAcl(DocId inheritId, boolean isDirectory,
      String fragmentName) throws IOException {
    Acl.Builder b = getAcl(inheritId, fragmentName, isDirectEntry);
    if (!isDirectory) {
      b.setInheritanceType(InheritanceType.LEAF_NODE);
    }
    return b.build();
  }

  public Acl getInheritableByAllDesendentFoldersAcl(DocId inheritId,
      String fragmentName) throws IOException {
    return getAcl(inheritId, fragmentName,
        isInheritableByAllDesendentFoldersEntry).build();
  }

  public Acl getInheritableByAllDesendentFilesAcl(DocId inheritId,
      String fragmentName) throws IOException {
    return getAcl(inheritId, fragmentName,
        isInheritableByAllDesendentFilesEntry).build();
  }

  public Acl getInheritableByChildFoldersOnlyAcl(DocId inheritId,
      String fragmentName) throws IOException {
    return getAcl(inheritId, fragmentName,
        isInheritableByChildFoldersOnlyEntry).build();
  }

  public Acl getInheritableByChildFilesOnlyAcl(DocId inheritId,
      String fragmentName) throws IOException {
    return getAcl(inheritId, fragmentName,
        isInheritableByChildFilesOnlyEntry).build();
  }

  public Acl getShareAcl() throws IOException {
    return getAcl(null, null, isDirectEntry)
        .setInheritanceType(InheritanceType.AND_BOTH_PERMIT).build();
  }

  private Acl.Builder getAcl(DocId inheritId, String fragmentName,
      Predicate<Set<AclEntryFlag>> predicate) throws IOException {
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();
    for (AclEntry entry : aclView.getAcl()) {
      if (!predicate.apply(entry.flags())) {
        continue;
      }
      if (filterAclEntry(entry)) {
        continue;
      }

      Principal principal;
      if (entry.principal() instanceof
          java.nio.file.attribute.GroupPrincipal) {
        principal = new GroupPrincipal(entry.principal().getName(), namespace);
      } else if (entry.principal() instanceof
          java.nio.file.attribute.UserPrincipal) {
        principal = new UserPrincipal(entry.principal().getName(), namespace);
      } else {
        log.log(Level.WARNING, "Unsupported Acl entry found: {0}", entry);
        continue;
      }

      if (entry.type() == AclEntryType.ALLOW) {
        permits.add(principal);
      } else if (entry.type() == AclEntryType.DENY) {
        denies.add(principal);
      }
    }

    return new Acl.Builder().setPermits(permits).setDenies(denies)
        .setInheritFrom(inheritId, fragmentName).setEverythingCaseInsensitive()
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES);
  }

  /**
   * Returns true if the provided {@link AclEntry} should be included in an Acl.
   *
   * @param entry The AclEntry to checked and added.
   */
  private boolean filterAclEntry(AclEntry entry) {
    String principalName = entry.principal().getName();

    if (!isSupportedWindowsAccount(principalName)) {
      if (isBuiltin(principalName)) {
        log.log(Level.FINEST, "Filtering BUILTIN ACE {0} for file {1}.",
            new Object[] { entry, doc });
        return true;
      }
    }

    if (isSid(principalName)) {
      log.log(Level.FINEST, "Filtering unresolved ACE {0} for file {1}.",
          new Object[] { entry, doc });
      return true;
    }

    if (!hasReadPermission(entry.permissions())) {
      log.log(Level.FINEST, "Filtering non-read ACE {0} for file {1}.",
          new Object[] { entry, doc });
      return true;
    }

    return false;
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
   * Returns true if the supplied account is an unresolved SID.
   */
  private final boolean isSid(String user) {
    // TODO(mifern): Implementation needed. Can use JNA ConvertStringSidToSid.
    // If ConvertStringSidToSid return true then it's a SID.
    return false;
  }

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is explicit
   * for this node, not inherited from another node.
   */
  private static final Predicate<Set<AclEntryFlag>> isDirectEntry =
      new Predicate<Set<AclEntryFlag>>() {
        public boolean apply(Set<AclEntryFlag> flags) {
          return !flags.contains(AclEntryFlag.INHERIT_ONLY);
        }
      };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by direct children folders only.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByChildFoldersOnlyEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.DIRECTORY_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by direct children files only.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByChildFilesOnlyEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.FILE_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by all desendent folders.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDesendentFoldersEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.DIRECTORY_INHERIT) &&
                  !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by all desendent files.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDesendentFilesEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.FILE_INHERIT) &&
                  !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };
}
