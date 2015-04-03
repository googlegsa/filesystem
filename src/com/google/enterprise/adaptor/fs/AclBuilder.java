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
import com.google.common.base.Predicates;
import com.google.enterprise.adaptor.Acl;
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
 * <p>
 * A note about the inheritance behaviours of ACEs, as described by Microsoft.
 * From this Microsoft page describing the application of inheritance flags to
 * ACEs:  http://support.microsoft.com/kb/220167
 * <p>
 * "This folder only": ACE flags = 0 : No inheritance applies to ACE.
 * <p>
 * "This folder, subfolders, and files":
 * ACE flags = FLAG_OBJECT_INHERIT | FLAG_CONTAINER_INHERIT :
 * All subordinate objects inherit this ACE, unless they are configured to
 * block ACL inheritance altogether.
 * <p>
 * "This folder and subfolders": ACE flags = FLAG_CONTAINER_INHERIT :
 * ACE propagates to subfolders of this container, but not to files within
 * this container.
 * <p>
 * "This folder and files": ACE flags = FLAG_OBJECT_INHERIT :
 * ACE propagates to files within this container, but not to subfolders.
 * <p>
 * "Subfolders and files only":
 * ACE flags = FLAG_INHERIT_ONLY | FLAG_OBJECT_INHERIT | FLAG_CONTAINER_INHERIT:
 * ACE does not apply to this container, but does propagate to both subfolders
 * and files contained within.
 * <p>
 * "Subfolders only":
 * ACE flags = FLAG_INHERIT_ONLY | FLAG_CONTAINER_INHERIT :
 * ACE does not apply to this container, but propagates to subfolders.
 * It does not propagate to contained files.
 * <p>
 * "Files only":
 * ACE flags = FLAG_INHERIT_ONLY | FLAG_OBJECT_INHERIT :
 * ACE does not apply to this container, but propagates to the files it
 * contains. Subfolders do not receive this ACE.
 * <p>
 * "Apply permissions to objects and/or containers within this container only":
 * ACE flags = * | FLAG_NO_PROPAGATE :
 * This flag limits inheritance only to those sub-objects that are immediately
 * subordinate to the current object.  It would be used in combination with
 * other flags to indicate whether the ACE applies to this container,
 * subordinate containers, and/or subordinate files.
 * <p>
 * More information regarding the explicit individual meanings of the ACE flags:
 * FLAG_INHERIT_ONLY - This flag indicates that this ACE does not apply to the
 * current object.
 * FLAG_CONTAINER_INHERIT - This flag indicates that subordinate containers
 * will inherit this ACE.
 * FLAG_OBJECT_INHERIT - This flag indicates that subordinate files will
 * inherit the ACE.
 * FLAG_NO_PROPAGATE - This flag indicates that the subordinate object will
 * not propagate the inherited ACE any further.
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

  public Acl.Builder getAcl() throws IOException {
    return getAcl(isDirectEntry);
  }

  public Acl.Builder getInheritableByAllDescendentFoldersAcl()
      throws IOException {
    return getAcl(isInheritableByAllDescendentFoldersEntry);
  }

  public Acl.Builder getInheritableByAllDescendentFilesAcl()
      throws IOException {
    return getAcl(isInheritableByAllDescendentFilesEntry);
  }

  public Acl.Builder getInheritableByChildFoldersOnlyAcl() throws IOException {
    return getAcl(isInheritableByChildFoldersOnlyEntry);
  }

  public Acl.Builder getInheritableByChildFilesOnlyAcl() throws IOException {
    return getAcl(isInheritableByChildFilesOnlyEntry);
  }

  Acl.Builder getFlattenedAcl() throws IOException {
    return getAcl(Predicates.<Set<AclEntryFlag>>alwaysTrue());
  }

  private Acl.Builder getAcl(Predicate<Set<AclEntryFlag>> predicate)
      throws IOException {
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();
    for (AclEntry entry : aclView.getAcl()) {
      if (!predicate.apply(entry.flags())) {
        continue;
      }
      if (filterOutAclEntry(entry)) {
        continue;
      }

      Principal principal;
      if (entry.principal()
          instanceof java.nio.file.attribute.GroupPrincipal) {
        principal = new GroupPrincipal(entry.principal().getName(), namespace);
      } else if (entry.principal() 
          instanceof java.nio.file.attribute.UserPrincipal) {
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
        .setEverythingCaseInsensitive();
  }

  /**
   * Returns true if provided {@link AclEntry} should be excluded from Acl.
   *
   * @param entry The AclEntry to check.
   */
  private boolean filterOutAclEntry(AclEntry entry) {
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
   * by all descendent folders.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDescendentFoldersEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.DIRECTORY_INHERIT)
                  && !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };

  /**
   * Returns true if the associated set of {@link AclEntryFlag} is inherited
   * by all descendent files.
   */
  private static final Predicate<Set<AclEntryFlag>>
      isInheritableByAllDescendentFilesEntry =
          new Predicate<Set<AclEntryFlag>>() {
            public boolean apply(Set<AclEntryFlag> flags) {
              return flags.contains(AclEntryFlag.FILE_INHERIT)
                  && !flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT);
            }
          };
}
