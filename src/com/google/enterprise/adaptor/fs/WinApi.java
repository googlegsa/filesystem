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

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Netapi32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.util.Arrays;
import java.util.List;

class WinApi {
  private WinApi() {
    // Prevent instantiation.
  }

  public interface Shlwapi extends StdCallLibrary {
    Shlwapi INSTANCE = (Shlwapi) Native.loadLibrary("Shlwapi",
        Shlwapi.class, W32APIOptions.UNICODE_OPTIONS);

    boolean PathIsNetworkPath(String pszPath);
    boolean PathIsUNC(String pszPath);
  }

  public interface Netapi32Ex extends Netapi32 {
    Netapi32Ex INSTANCE = (Netapi32Ex) Native.loadLibrary(
        "Netapi32", Netapi32Ex.class, W32APIOptions.UNICODE_OPTIONS);
  
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

    public int NetDfsGetSecurity(String DfsEntryPath, int SecurityInformation,
        PointerByReference ppSecurityDescriptor,
        IntByReference lpcbSecurityDescriptor);

    public int NetDfsGetInfo(String DfsEntryPath, String ServerName,
        String ShareName, int Level, PointerByReference Buffer);

    public static final int DFS_STORAGE_STATE_ONLINE = 2;

    public static class DFS_INFO_3 extends Structure {
      public WString EntryPath;
      public WString Comment;
      public DWORD State;
      public DWORD NumberOfStorages;
      public Pointer Storage;
      protected DFS_STORAGE_INFO[] StorageInfos;
  
      public DFS_INFO_3(Pointer m) {
        useMemory(m);
        read();
      }
  
      @Override
      public void read() {
        super.read();
  
        // TODO(mifren): There should be a better way of getting JNA to
        // read the array of DFS_STORAGE_INFO.
        StorageInfos = new DFS_STORAGE_INFO[NumberOfStorages.intValue()];
        for (int i = 0; i < StorageInfos.length; i++) {
          StorageInfos[i] = new DFS_STORAGE_INFO(Storage.share(i * 24));
        }
      }
  
      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("EntryPath", "Comment", "State",
            "NumberOfStorages", "Storage");
      }
    }
  
    public static class DFS_INFO_150 extends Structure {
      public ULONG SdLengthReserved;
      public Pointer pSecurityDescriptor;
  
      public DFS_INFO_150(Pointer m) {
        useMemory(m);
        read();
      }
  
      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("SdLengthReserved", "pSecurityDescriptor");
      }
    }
  
    public static class DFS_STORAGE_INFO extends Structure {
      public ULONG State;
      public WString ServerName;
      public WString ShareName;
  
      public DFS_STORAGE_INFO(Pointer m) {
        useMemory(m);
        read();
      }
  
      @Override
      protected List<String> getFieldOrder() {
        return Arrays.asList("State", "ServerName", "ShareName");
      }
    }
  }
}
