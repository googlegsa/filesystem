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

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Tlhelp32.PROCESSENTRY32;
import com.sun.jna.platform.win32.WinBase.FILETIME;
import com.sun.jna.platform.win32.WinBase.OVERLAPPED;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.WinBase.STARTUPINFO;
import com.sun.jna.platform.win32.WinBase.SYSTEMTIME;
import com.sun.jna.platform.win32.WinNT.FILE_NOTIFY_INFORMATION;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import java.nio.Buffer;

/**
 * An implementation of the Kernel32 Interface that throws
 * UnsupportedOperationException for everything.  Tests may
 * subclass this and override those methods used by the object
 * under test.
 */
public class UnsupportedKernel32 implements Kernel32 {

  @Override
  public int FormatMessage(int dwFlags, Pointer lpSource, int dwMessageId,
      int dwLanguageId, Buffer lpBuffer, int nSize, Pointer va_list) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadFile(HANDLE hFile, Buffer lpBuffer,
      int nNumberOfBytesToRead, IntByReference lpNumberOfBytesRead,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer LocalFree(Pointer hLocal) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer GlobalFree(Pointer hGlobal) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HMODULE GetModuleHandle(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetSystemTime(SYSTEMTIME lpSystemTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetLocalTime(SYSTEMTIME lpSystemTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetTickCount() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetCurrentThreadId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE GetCurrentThread() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetCurrentProcessId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE GetCurrentProcess() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetProcessId(HANDLE process) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetProcessVersion(int processId) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetExitCodeProcess(HANDLE hProcess,
      IntByReference lpExitCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean TerminateProcess(HANDLE hProcess, int uExitCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetLastError() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void SetLastError(int dwErrCode) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetDriveType(String lpRootPathName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int FormatMessage(int dwFlags, Pointer lpSource, int dwMessageId,
      int dwLanguageId, Pointer lpBuffer, int nSize, Pointer va_list) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int FormatMessage(int dwFlags, Pointer lpSource, int dwMessageId,
      int dwLanguageId, PointerByReference lpBuffer, int nSize,
      Pointer va_list) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateFile(String lpFileName, int dwDesiredAccess,
      int dwShareMode, SECURITY_ATTRIBUTES lpSecurityAttributes,
      int dwCreationDisposition, int dwFlagsAndAttributes,
      HANDLE hTemplateFile) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CopyFile(String lpExistingFileName, String lpNewFileName,
      boolean bFailIfExists) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean MoveFile(String lpExistingFileName, String lpNewFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean MoveFileEx(String lpExistingFileName, String lpNewFileName,
      DWORD dwFlags) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateDirectory(String lpPathName,
      SECURITY_ATTRIBUTES lpSecurityAttributes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadFile(HANDLE hFile, Pointer lpBuffer,
      int nNumberOfBytesToRead, IntByReference lpNumberOfBytesRead,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateIoCompletionPort(HANDLE FileHandle,
      HANDLE ExistingCompletionPort, Pointer CompletionKey,
      int NumberOfConcurrentThreads) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetQueuedCompletionStatus(HANDLE CompletionPort,
      IntByReference lpNumberOfBytes,
      ULONG_PTRByReference lpCompletionKey,
      PointerByReference lpOverlapped, int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean PostQueuedCompletionStatus(HANDLE CompletionPort,
      int dwNumberOfBytesTransferred, Pointer dwCompletionKey,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WaitForSingleObject(HANDLE hHandle, int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int WaitForMultipleObjects(int nCount, HANDLE[] hHandle,
      boolean bWaitAll, int dwMilliseconds) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DuplicateHandle(HANDLE hSourceProcessHandle,
      HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
      HANDLEByReference lpTargetHandle,
      int dwDesiredAccess, boolean bInheritHandle, int dwOptions) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CloseHandle(HANDLE hObject) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean ReadDirectoryChangesW(HANDLE directory,
      FILE_NOTIFY_INFORMATION info, int length,
      boolean watchSubtree, int notifyFilter,
      IntByReference bytesReturned, OVERLAPPED overlapped,
      OVERLAPPED_COMPLETION_ROUTINE completionRoutine) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetShortPathName(String lpszLongPath, char[] lpdzShortPath,
            int cchBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer LocalAlloc(int uFlags, int uBytes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WriteFile(HANDLE hFile, byte[] lpBuffer,
      int nNumberOfBytesToWrite, IntByReference lpNumberOfBytesWritten,
      OVERLAPPED lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateEvent(SECURITY_ATTRIBUTES lpEventAttributes,
      boolean bManualReset, boolean bInitialState, String lpName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetEvent(HANDLE hEvent) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean PulseEvent(HANDLE hEvent) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateFileMapping(HANDLE hFile,
      SECURITY_ATTRIBUTES lpAttributes, int flProtect,
      int dwMaximumSizeHigh, int dwMaximumSizeLow, String lpName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pointer MapViewOfFile(HANDLE hFileMappingObject, int dwDesiredAccess,
      int dwFileOffsetHigh, int dwFileOffsetLow, int dwNumberOfBytesToMap) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean UnmapViewOfFile(Pointer lpBaseAddress) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetComputerName(char[] buffer, IntByReference lpnSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenThread(int dwDesiredAccess, boolean bInheritHandle,
      int dwThreadId) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateProcess(String lpApplicationName, String lpCommandLine,
      SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      boolean bInheritHandles, DWORD dwCreationFlags,
      Pointer lpEnvironment, String lpCurrentDirectory,
      STARTUPINFO lpStartupInfo,
      PROCESS_INFORMATION lpProcessInformation) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreateProcessW(String lpApplicationName, char[] lpCommandLine,
      SECURITY_ATTRIBUTES lpProcessAttributes,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      boolean bInheritHandles, DWORD dwCreationFlags,
      Pointer lpEnvironment, String lpCurrentDirectory,
      STARTUPINFO lpStartupInfo,
      PROCESS_INFORMATION lpProcessInformation) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE OpenProcess(int fdwAccess, boolean fInherit, int IDProcess) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetTempPath(DWORD nBufferLength, char[] buffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetVersion() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVersionEx(OSVERSIONINFO lpVersionInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetVersionEx(OSVERSIONINFOEX lpVersionInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetSystemInfo(SYSTEM_INFO lpSystemInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void GetNativeSystemInfo(SYSTEM_INFO lpSystemInfo) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean IsWow64Process(HANDLE hProcess, IntByReference Wow64Process) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetLogicalProcessorInformation(Pointer buffer,
      DWORDByReference returnLength) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GlobalMemoryStatusEx(MEMORYSTATUSEX lpBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetFileTime(HANDLE hFile, FILETIME lpCreationTime,
      FILETIME lpLastAccessTime, FILETIME lpLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int SetFileTime(HANDLE hFile, FILETIME lpCreationTime,
      FILETIME lpLastAccessTime, FILETIME lpLastWriteTime) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetFileAttributes(String lpFileName, DWORD dwFileAttributes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetLogicalDriveStrings(DWORD nBufferLength, char[] lpBuffer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetDiskFreeSpaceEx(String lpDirectoryName,
      LARGE_INTEGER lpFreeBytesAvailable,
      LARGE_INTEGER lpTotalNumberOfBytes,
      LARGE_INTEGER lpTotalNumberOfFreeBytes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeleteFile(String filename) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean CreatePipe(HANDLEByReference hReadPipe,
      HANDLEByReference hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes,
      int nSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetHandleInformation(HANDLE hObject, int dwMask, int dwFlags) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetFileAttributes(String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetFileType(HANDLE hFile) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean DeviceIoControl(HANDLE hDevice, int dwIoControlCode,
      Pointer lpInBuffer, int nInBufferSize, Pointer lpOutBuffer,
      int nOutBufferSize, IntByReference lpBytesReturned,
      Pointer lpOverlapped) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean GetDiskFreeSpaceEx(String lpDirectoryName,
      LongByReference lpFreeBytesAvailable,
      LongByReference lpTotalNumberOfBytes,
      LongByReference lpTotalNumberOfFreeBytes) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean Process32First(HANDLE hSnapshot, PROCESSENTRY32 lppe) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean Process32Next(HANDLE hSnapshot, PROCESSENTRY32 lppe) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean SetEnvironmentVariable(String lpName, String lpValue) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetEnvironmentVariable(String lpName, char[] lpBuffer, int nSize) {
    throw new UnsupportedOperationException();
  }

  @Override
  public LCID GetSystemDefaultLCID() {
    throw new UnsupportedOperationException();
  }

  @Override
  public LCID GetUserDefaultLCID() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int GetPrivateProfileInt(String appName, String keyName,
      int defaultValue, String fileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public DWORD GetPrivateProfileString(String lpAppName, String lpKeyName,
      String lpDefault, char[] lpReturnedString, DWORD nSize,
      String lpFileName) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean WritePrivateProfileString(String lpAppName, String lpKeyName,
      String lpString, String lpFileName) {
    throw new UnsupportedOperationException();
  }
}
