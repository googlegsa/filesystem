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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Advapi32Util.Account;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.LMErr;
import com.sun.jna.platform.win32.Netapi32;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.SID_NAME_USE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Factory for generating various {@code AclFileAttributeViews}
 * for Windows files.
 */
public class WindowsAclFileAttributeViews {

  private static final Logger LOG = 
      Logger.getLogger(WindowsAclFileAttributeViews.class.getName());

  private static final Kernel32 KERNEL32 = (Kernel32) Native.loadLibrary(
      "Kernel32", Kernel32.class, W32APIOptions.UNICODE_OPTIONS);

  private static final Advapi32 ADVAPI32 = (Advapi32) Native.loadLibrary(
      "Advapi32", Advapi32.class, W32APIOptions.UNICODE_OPTIONS);

  /** This pattern parses a UNC path to get the host and share details. */
  private static final Pattern UNC_PATTERN =
      Pattern.compile("^\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)");


  private WindowsAclFileAttributeViews() {
    // Prevents instantiation.
  }

  /**
   * Returns the access control list. The returned list does not include any
   * permissions that the file inherited from its parent.
   *
   * @param doc a Path representing a Windows file or directory
   * @return AclFileAttributeView of direct ACL entries
   */
  public static AclFileAttributeView  getAclView(Path doc) throws IOException {
    String pathname = doc.toRealPath(LinkOption.NOFOLLOW_LINKS).toString();
    WinNT.ACCESS_ACEStructure[] aces =
        getFileSecurity(pathname, WinNT.DACL_SECURITY_INFORMATION);
    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      if ((ace.AceFlags & WinNT.INHERITED_ACE) == 0) {
        AclEntry aclEntry = newAclEntry(ace);
        if (aclEntry != null) {
          builder.add(aclEntry);
        }
      }
    }
    List<AclEntry> acl = builder.build();
    if (LOG.isLoggable(Level.FINEST)) {
      LOG.log(Level.FINEST, "Direct ACL for {0}: {1}",
              new Object[] { pathname, acl.toString() });
    }
    return new WindowsAclFileAttributeView(acl);
  }

  /**
   * Returns an access control list.  The returned list contains only
   * permissions that were inherited from the file's parent.
   * <p/>
   * Note that there is a distinct difference between a return value of
   * {@code null} and an empty list. A return of {@code null} indicates
   * that the file did not inherit any aces from its parent.  An empty
   * {@code List} indicates that the file did inherit some permissions
   * from its parent, but inherited no {@code ACCESS_ALLOWED} or
   * {@code ACCESS_DENIED} permissions for user or group accounts.
   *
   * @param doc a Path representing a Windows file or directory
   * @return AclFileAttributeView of inherited ACL entries, or {@code null}
   *         if there were no inherited ACLs entries.
   */
  public static AclFileAttributeView getInheritedAclView(Path doc) 
      throws IOException {
    String pathname = doc.toRealPath(LinkOption.NOFOLLOW_LINKS).toString();
    WinNT.ACCESS_ACEStructure[] aces =
        getFileSecurity(pathname, WinNT.UNPROTECTED_DACL_SECURITY_INFORMATION);
    boolean hasInheritedAces = false;
    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();
    for (WinNT.ACCESS_ACEStructure ace : aces) {
      if ((ace.AceFlags & WinNT.INHERITED_ACE) == WinNT.INHERITED_ACE) {
        hasInheritedAces = true;
        AclEntry aclEntry = newAclEntry(ace);
        if (aclEntry != null) {
          builder.add(aclEntry);
        }
      }
    }

    // If there any inherited ACEs return an AclView, even if it is empty.
    // If there were no inherited ACEs, return null.
    if (hasInheritedAces) {
      List<AclEntry> acl = builder.build();
      if (LOG.isLoggable(Level.FINEST)) {
        LOG.log(Level.FINEST, "Inherited ACL for {0}: {1}",
                new Object[] { pathname, acl.toString() });
      }
      return new WindowsAclFileAttributeView(acl);
    } else {
      LOG.log(Level.FINEST, "Inherited ACL for {0}: none", pathname);
      return null;
    }
  }

  /**
   * Returns the access control list for the file share which contains
   * the supplied file.
   *
   * @param doc a Path representing a Windows file or directory
   * @return AclFileAttributeView of ACL entries imposed by the share
   */
  public static AclFileAttributeView getShareAclView(Path doc)
      throws IOException, UnsupportedOperationException {
    if (Shlwapi.INSTANCE.PathIsUNC(doc.toString())) {
      LOG.log(Level.FINEST, "Using a UNC path.");
      return getUncShareAclView(doc.toString());
    } else if (Shlwapi.INSTANCE.PathIsNetworkPath(doc.toString())) {
      LOG.log(Level.FINEST, "Using a mapped drive.");
      // Call WNetGetUniversalNameW with the size needed for 
      // UNIVERSAL_NAME_INFO. If WNetGetUniversalNameW returns ERROR_MORE_DATA
      // that indicates that a larger buffer is needed. If this happens, make
      // a second call to WNetGetUniversalNameW with a buffer big enough.
      Mpr mprlib = Mpr.INSTANCE;
      Memory buf = new Memory(1024);
      IntByReference bufSize = new IntByReference((int) buf.size());
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
      LOG.log(Level.FINEST, "Using a local drive.");
      return new WindowsAclFileAttributeView(ImmutableList.<AclEntry>of());
    }
    // TODO(mifern): For a local drive, mapped and UNC the share Acl must also
    // include the Acls from the config point to the root.
  }

  private static AclFileAttributeView getUncShareAclView(String uncPath)
      throws IOException {
    Matcher match = UNC_PATTERN.matcher(uncPath);
    if (!match.find()) {
      throw new IOException("The UNC path " + uncPath + " is not valid. "
          + "A UNC path of the form \\\\<host>\\<share> is required.");
    }
    String host = match.group(1);
    String share = match.group(2);
    LOG.log(Level.FINEST, "UNC: host: {0}, share: {1}.",
        new Object[] { host, share });
    return getShareAclView(host, share);
  }
  
  private static AclFileAttributeView getShareAclView(String host, String share)
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

    WinNT.SECURITY_DESCRIPTOR_RELATIVE sdr =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE(info.shi502_security_descriptor);
    WinNT.ACL dacl = sdr.getDiscretionaryACL();

    ImmutableList.Builder<AclEntry> builder = ImmutableList.builder();    
    for (WinNT.ACCESS_ACEStructure ace : dacl.getACEStructures()) {
      AclEntry entry = newAclEntry(ace);
      if (entry != null) {
        builder.add(entry);
      }
    }

    List<AclEntry> acl = builder.build();
    if (LOG.isLoggable(Level.FINEST)) {
      LOG.log(Level.FINEST, "Share ACL for \\\\{0}\\{1}: {2}",
              new Object[] { host, share, acl.toString() });
    }
    return new WindowsAclFileAttributeView(acl);
  }


  private static interface Netapi32Ex extends Netapi32 {
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
        return ImmutableList.<String>of(
            "shi502_netname", "shi502_type", "shi502_remark",
            "shi502_permissions", "shi502_max_uses", "shi502_current_uses",
            "shi502_path", "shi502_passwd", "shi502_reserved",
            "shi502_security_descriptor"
            );
      }
    }
  }

  /**
   * Creates an {@link AclEntry} from a {@code WinNT.ACCESS_ACEStructure}.
   *
   * @param ace Windows ACE returned by JNA
   * @return AclEntry representing the ace, or {@code null} if a valid
   *         AclEntry could not be created from the ace.
   */
  private static AclEntry newAclEntry(WinNT.ACCESS_ACEStructure ace) {
    AclEntryType type;
    if (ace.AceType == WinNT.ACCESS_ALLOWED_ACE_TYPE) {
      type = AclEntryType.ALLOW;
    } else if (ace.AceType == WinNT.ACCESS_DENIED_ACE_TYPE) {
      type = AclEntryType.DENY;
    } else {
      LOG.log(Level.FINEST, "Skipping ACE with unsupported access type: {0}.",
              ace.AceType);
      return null;
    }

    UserPrincipal userPrincipal = newUserPrincipal(ace.getSID());
    if (userPrincipal == null) {
      return null;
    }

    Set<AclEntryFlag> flags = EnumSet.noneOf(AclEntryFlag.class);
    if ((ace.AceFlags & WinNT.OBJECT_INHERIT_ACE) != 0) {
      flags.add(AclEntryFlag.FILE_INHERIT);
    }
    if ((ace.AceFlags & WinNT.CONTAINER_INHERIT_ACE) != 0) {
      flags.add(AclEntryFlag.DIRECTORY_INHERIT);
    }
    if ((ace.AceFlags & WinNT.NO_PROPAGATE_INHERIT_ACE) != 0) {
      flags.add(AclEntryFlag.NO_PROPAGATE_INHERIT);
    }
    if ((ace.AceFlags & WinNT.INHERIT_ONLY_ACE) != 0) {
      flags.add(AclEntryFlag.INHERIT_ONLY);
    }

    Set<AclEntryPermission> perms = EnumSet.noneOf(AclEntryPermission.class);
    if ((ace.Mask & WinNT.FILE_READ_DATA) > 0) {
      perms.add(AclEntryPermission.READ_DATA);
    }
    if ((ace.Mask & WinNT.FILE_WRITE_DATA) > 0) {
      perms.add(AclEntryPermission.WRITE_DATA);
    }
    if ((ace.Mask & WinNT.FILE_APPEND_DATA ) > 0) {
      perms.add(AclEntryPermission.APPEND_DATA);
    }
    if ((ace.Mask & WinNT.FILE_READ_EA) > 0) {
      perms.add(AclEntryPermission.READ_NAMED_ATTRS);
    }
    if ((ace.Mask & WinNT.FILE_WRITE_EA) > 0) {
      perms.add(AclEntryPermission.WRITE_NAMED_ATTRS);
    }
    if ((ace.Mask & WinNT.FILE_EXECUTE) > 0) {
      perms.add(AclEntryPermission.EXECUTE);
    }
    if ((ace.Mask & WinNT.FILE_DELETE_CHILD ) > 0) {
      perms.add(AclEntryPermission.DELETE_CHILD);
    }
    if ((ace.Mask & WinNT.FILE_READ_ATTRIBUTES) > 0) {
      perms.add(AclEntryPermission.READ_ATTRIBUTES);
    }
    if ((ace.Mask & WinNT.FILE_WRITE_ATTRIBUTES) > 0) {
      perms.add(AclEntryPermission.WRITE_ATTRIBUTES);
    }
    if ((ace.Mask & WinNT.DELETE) > 0) {
      perms.add(AclEntryPermission.DELETE);
    }
    if ((ace.Mask & WinNT.READ_CONTROL) > 0) {
      perms.add(AclEntryPermission.READ_ACL);
    }
    if ((ace.Mask & WinNT.WRITE_DAC) > 0) {
      perms.add(AclEntryPermission.WRITE_ACL);
    }
    if ((ace.Mask & WinNT.WRITE_OWNER) > 0) {
      perms.add(AclEntryPermission.WRITE_OWNER);
    }
    if ((ace.Mask & WinNT.SYNCHRONIZE) > 0) {
      perms.add(AclEntryPermission.SYNCHRONIZE);
    }
    
    return AclEntry.newBuilder()
        .setType(type)
        .setPrincipal(userPrincipal)
        .setFlags(flags)
        .setPermissions(perms)
        .build();
  }
  
  private static final String[] SID_TYPE_NAMES = {
    "Unknown", "User", "Group", "Domain", "Alias", "Well-known Group",
    "Deleted", "Invalid", "Computer" };

  private static String getSidTypeString(int sidType) {
    if (sidType < 0 || sidType > SID_TYPE_NAMES.length) {
      return SID_TYPE_NAMES[0];
    } else {
      return SID_TYPE_NAMES[sidType];
    }
  }

  /**
   * Generates a {@link UserPrincipal} or {@link GroupPrincipal} from a
   * {@code SID}.
   */
  private static UserPrincipal newUserPrincipal(WinNT.PSID sid) {
    Account account = Advapi32Util.getAccountBySid(sid);
    if (account == null) {
      LOG.log(Level.FINEST, "Skipping ACE with unresolvable SID: {0}.",
              Advapi32Util.convertSidToStringSid(sid));
      return null;
    }
    String name;
    if (Strings.isNullOrEmpty(account.name)) {
      name = account.sidString;
    } else if (Strings.isNullOrEmpty(account.domain)) {
      name = account.name;
    } else {
      name = account.domain + "\\" + account.name;
    }
    switch (account.accountType) {
      case SID_NAME_USE.SidTypeUser:
        return new User(account.sidString, account.accountType, name);        
      case SID_NAME_USE.SidTypeGroup:
      case SID_NAME_USE.SidTypeAlias:
      case SID_NAME_USE.SidTypeWellKnownGroup:
        return new Group(account.sidString, account.accountType, name);
      default:
        LOG.log(Level.FINEST,
            "Skipping ACE with unsupported account type {0} ({1}).", 
            new Object[] { name, getSidTypeString(account.accountType) });
        return null;
    }
  }

  private static class User implements UserPrincipal {
    // String representation of SID.
    private final String sidString;

    // SID type - one of WinNT.SID_NAME_USE.
    private final int sidType;
    
    // Account name (if available) or SID string.
    private final String accountName;

    User(String sidString, int sidType, String accountName) {
      this.sidString = sidString;
      this.sidType = sidType;
      this.accountName = accountName;
    }

    public String sidString() {
      return sidString;
    }

    @Override
    public String getName() {
      return accountName;
    }

    @Override
    public String toString() {
      return accountName + " (" + getSidTypeString(sidType) + ")";
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!(obj instanceof User)) {
        return false;
      }
      User other = (User) obj;
      return this.sidString.equals(other.sidString);
    }

    @Override
    public int hashCode() {
      return sidString.hashCode();
    }
  }

  private static class Group extends User implements GroupPrincipal {
    Group(String sidString, int sidType, String accountName) {
      super(sidString, sidType, accountName);
    }
  }

  private static class WindowsAclFileAttributeView
      implements AclFileAttributeView {
    private final List<AclEntry> acl;

    WindowsAclFileAttributeView(List<AclEntry> acl) {
      this.acl = acl;
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

  private static interface Shlwapi extends StdCallLibrary {
    Shlwapi INSTANCE = (Shlwapi) Native.loadLibrary("Shlwapi",
        Shlwapi.class, W32APIOptions.UNICODE_OPTIONS);

    boolean PathIsNetworkPath(String pszPath);
    boolean PathIsUNC(String pszPath);
  }

  private static interface Mpr extends StdCallLibrary {
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
        return ImmutableList.<String>of("lpUniversalName");
      }
    }
  }

  /** Uses JNA to call native Windows {@code GetFileSecurity} function. */
  private static WinNT.ACCESS_ACEStructure[] getFileSecurity(String pathname, int daclType)
      throws IOException {
    WString wpath = new WString(pathname);
    IntByReference lengthNeeded = new IntByReference();

    if (ADVAPI32.GetFileSecurity(wpath, daclType, null, 0, lengthNeeded)) {
      throw new RuntimeException("GetFileSecurity was expected to fail with "
                                 + "ERROR_INSUFFICIENT_BUFFER");
    }

    int rc = KERNEL32.GetLastError();
    if (lengthNeeded.getValue() == 0 ||
        rc != W32Errors.ERROR_INSUFFICIENT_BUFFER) {
      throw new IOException("Failed GetFileSecurity", new Win32Exception(rc));
    }

    Memory memory = new Memory(lengthNeeded.getValue());
    if (!ADVAPI32.GetFileSecurity(wpath, daclType, memory, 0, lengthNeeded)) {
      throw new IOException("Failed GetFileSecurity",
                            new Win32Exception(KERNEL32.GetLastError()));
    }

    WinNT.SECURITY_DESCRIPTOR_RELATIVE securityDescriptor =
        new WinNT.SECURITY_DESCRIPTOR_RELATIVE(memory);
    return securityDescriptor.getDiscretionaryACL().getACEStructures();
  }
}
