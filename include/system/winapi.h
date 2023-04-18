// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

//===-- wasmedge/system/winapi.h - Wrapper for Windows API-----------------===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains helper to call Windows API.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "common/defines.h"
#include <cstdint>

#if WASMEDGE_OS_WINDOWS

#if defined(__GNUC__) || defined(__clang__)
#define WASMEDGE_WINAPI_DETAIL_EXTENSION __extension__
#define WASMEDGE_WINAPI_FORCEINLINE [[gnu::always_inline]]
#define WASMEDGE_WINAPI_SYMBOL_IMPORT [[gnu::dllimport]]
#else
#define WASMEDGE_WINAPI_DETAIL_EXTENSION
#define WASMEDGE_WINAPI_FORCEINLINE __forceinline
#define WASMEDGE_WINAPI_SYMBOL_IMPORT __declspec(dllimport)
#endif

#if defined(_M_IX86) || defined(__i386__)
#ifdef __GNUC__
#define WASMEDGE_WINAPI_WINAPI_CC [[gnu::stdcall]]
#else
#define WASMEDGE_WINAPI_WINAPI_CC __stdcall
#endif
#else
#define WASMEDGE_WINAPI_WINAPI_CC
#endif

// _WIN32_WINNT version constants
#define _WIN32_WINNT_NT4 0x0400          // Windows NT 4.0
#define _WIN32_WINNT_WIN2K 0x0500        // Windows 2000
#define _WIN32_WINNT_WINXP 0x0501        // Windows XP
#define _WIN32_WINNT_WS03 0x0502         // Windows Server 2003
#define _WIN32_WINNT_WIN6 0x0600         // Windows Vista
#define _WIN32_WINNT_VISTA 0x0600        // Windows Vista
#define _WIN32_WINNT_WS08 0x0600         // Windows Server 2008
#define _WIN32_WINNT_LONGHORN 0x0600     // Windows Vista
#define _WIN32_WINNT_WIN7 0x0601         // Windows 7
#define _WIN32_WINNT_WIN8 0x0602         // Windows 8
#define _WIN32_WINNT_WINBLUE 0x0603      // Windows 8.1
#define _WIN32_WINNT_WINTHRESHOLD 0x0A00 // Windows 10
#define _WIN32_WINNT_WIN10 0x0A00        // Windows 10

#define NTDDI_WIN2K 0x05000000
#define NTDDI_WINXP 0x05010000
#define NTDDI_WS03 0x05020000
#define NTDDI_WIN6 0x06000000
#define NTDDI_VISTA 0x06000000
#define NTDDI_WS08 0x06000000
#define NTDDI_LONGHORN 0x06000000
#define NTDDI_WIN7 0x06010000
#define NTDDI_WIN8 0x06020000
#define NTDDI_WINBLUE 0x06030000
#define NTDDI_WINTHRESHOLD 0x0A000000
#define NTDDI_WIN10 0x0A000000
#define NTDDI_WIN10_TH2 0x0A000001
#define NTDDI_WIN10_RS1 0x0A000002
#define NTDDI_WIN10_RS2 0x0A000003
#define NTDDI_WIN10_RS3 0x0A000004
#define NTDDI_WIN10_RS4 0x0A000005
#define NTDDI_WIN10_RS5 0x0A000006
#define NTDDI_WIN10_19H1 0x0A000007
#define WDK_NTDDI_VERSION NTDDI_WIN10_19H1

#ifndef _WIN32_WINNT
// Set default version to Windows 8
#define _WIN32_WINNT _WIN32_WINNT_WIN8
#define NTDDI_VERSION NTDDI_WIN8
#else
#ifndef NTDDI_VERSION
#define NTDDI_VERSION _WIN32_WINNT##0000
#endif
#endif

namespace WasmEdge::winapi {

using BOOL_ = int;
using PBOOL_ = BOOL_ *;
using LPBOOL_ = BOOL_ *;
using BYTE_ = uint8_t;
using PBYTE_ = BYTE_ *;
using LPBYTE_ = BYTE_ *;
using UCHAR_ = uint8_t;
using PUCHAR_ = UCHAR_ *;
using BOOLEAN_ = BYTE_;
using PBOOLEAN_ = BOOLEAN_ *;
using WORD_ = uint16_t;
using PWORD_ = WORD_ *;
using LPWORD_ = WORD_ *;
using DWORD_ = uint32_t;
using PDWORD_ = DWORD_ *;
using LPDWORD_ = DWORD_ *;
using VOID_ = void;
using PVOID_ = void *;
using LPVOID_ = void *;
using LPCVOID_ = const void *;
using HANDLE_ = void *;
using PHANDLE_ = HANDLE_ *;

using SHORT_ = short;
using PSHORT_ = SHORT_ *;
using USHORT_ = unsigned short;
using PUSHORT_ = USHORT_ *;
using INT_ = int;
using PINT_ = INT_ *;
using LPINT_ = INT_ *;
using UINT_ = unsigned int;
using PUINT_ = UINT_ *;
using LONG_ = int32_t;
using ULONG_ = uint32_t;
using PLONG_ = LONG_ *;
using LPLONG_ = LONG_ *;
using PULONG_ = ULONG_ *;
using LONGLONG_ = int64_t;
using ULONGLONG_ = uint64_t;

using ULONG64_ = uint64_t;

using INT_PTR_ = intptr_t;
using UINT_PTR_ = uintptr_t;
using ULONG_PTR_ = uintptr_t;

using SIZE_T_ = size_t;

using CHAR_ = char;
using LPSTR_ = CHAR_ *;
using PCSTR_ = const CHAR_ *;
using LPCSTR_ = const CHAR_ *;
using WCHAR_ = wchar_t;
using PWSTR_ = WCHAR_ *;
using LPWSTR_ = WCHAR_ *;
using PCWSTR_ = const WCHAR_ *;
using LPCWSTR_ = const WCHAR_ *;

using LARGE_INTEGER_ = union _LARGE_INTEGER {
  WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
    DWORD_ LowPart;
    LONG_ HighPart;
  };
  struct {
    DWORD_ LowPart;
    LONG_ HighPart;
  } u;
  LONGLONG_ QuadPart;
};

using ULARGE_INTEGER_ = union _ULARGE_INTEGER {
  WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
    DWORD_ LowPart;
    DWORD_ HighPart;
  };
  struct {
    DWORD_ LowPart;
    DWORD_ HighPart;
  } u;
  ULONGLONG_ QuadPart;
};

using SECURITY_ATTRIBUTES_ = struct _SECURITY_ATTRIBUTES {
  DWORD_ nLength;
  LPVOID_ lpSecurityDescriptor;
  BOOL_ bInheritHandle;
};
using PSECURITY_ATTRIBUTES_ = SECURITY_ATTRIBUTES_ *;
using LPSECURITY_ATTRIBUTES_ = SECURITY_ATTRIBUTES_ *;

#if NTDDI_VERSION >= NTDDI_WIN8
using CREATEFILE2_EXTENDED_PARAMETERS_ =
    struct _CREATEFILE2_EXTENDED_PARAMETERS {
  DWORD_ dwSize;
  DWORD_ dwFileAttributes;
  DWORD_ dwFileFlags;
  DWORD_ dwSecurityQosFlags;
  LPSECURITY_ATTRIBUTES_ lpSecurityAttributes;
  HANDLE_ hTemplateFile;
};
using LPCREATEFILE2_EXTENDED_PARAMETERS_ = CREATEFILE2_EXTENDED_PARAMETERS_ *;
#endif

using FILETIME_ = struct _FILETIME {
  DWORD_ dwLowDateTime;
  DWORD_ dwHighDateTime;
};
using LPFILETIME_ = FILETIME_ *;

static inline constexpr const DWORD_ MAX_PATH_ = 260;
using WIN32_FIND_DATAW_ = struct _WIN32_FIND_DATAW {
  DWORD_ dwFileAttributes;
  FILETIME_ ftCreationTime;
  FILETIME_ ftLastAccessTime;
  FILETIME_ ftLastWriteTime;
  DWORD_ nFileSizeHigh;
  DWORD_ nFileSizeLow;
  DWORD_ dwReserved0;
  DWORD_ dwReserved1;
  WCHAR_ cFileName[MAX_PATH_];
  WCHAR_ cAlternateFileName[14];
  [[deprecated]] DWORD_ dwFileType;    // Obsolete. Do not use
  [[deprecated]] DWORD_ dwCreatorType; // Obsolete. Do not use
  [[deprecated]] WORD_ wFinderFlags;   // Obsolete. Do not use
};
using PWIN32_FIND_DATAW_ = WIN32_FIND_DATAW_ *;
using LPWIN32_FIND_DATAW_ = WIN32_FIND_DATAW_ *;

using BY_HANDLE_FILE_INFORMATION_ = struct _BY_HANDLE_FILE_INFORMATION {
  DWORD_ dwFileAttributes;
  FILETIME_ ftCreationTime;
  FILETIME_ ftLastAccessTime;
  FILETIME_ ftLastWriteTime;
  DWORD_ dwVolumeSerialNumber;
  DWORD_ nFileSizeHigh;
  DWORD_ nFileSizeLow;
  DWORD_ nNumberOfLinks;
  DWORD_ nFileIndexHigh;
  DWORD_ nFileIndexLow;
};
using LPBY_HANDLE_FILE_INFORMATION_ = BY_HANDLE_FILE_INFORMATION_ *;

#if NTDDI_VERSION >= NTDDI_VISTA
using FILE_END_OF_FILE_INFO_ = struct _FILE_END_OF_FILE_INFO {
  LARGE_INTEGER_ EndOfFile;
};

using FILE_ATTRIBUTE_TAG_INFO_ = struct _FILE_ATTRIBUTE_TAG_INFO {
  DWORD_ FileAttributes;
  DWORD_ ReparseTag;
};

using FILE_INFO_BY_HANDLE_CLASS_ = enum _FILE_INFO_BY_HANDLE_CLASS {
  FileBasicInfo_,
  FileStandardInfo_,
  FileNameInfo_,
  FileRenameInfo_,
  FileDispositionInfo_,
  FileAllocationInfo_,
  FileEndOfFileInfo_,
  FileStreamInfo_,
  FileCompressionInfo_,
  FileAttributeTagInfo_,
  FileIdBothDirectoryInfo_,
  FileIdBothDirectoryRestartInfo_,
  FileIoPriorityHintInfo_,
  FileRemoteProtocolInfo_,
  FileFullDirectoryInfo_,
  FileFullDirectoryRestartInfo_,
#if NTDDI_VERSION >= NTDDI_WIN8
  FileStorageInfo_,
  FileAlignmentInfo_,
  FileIdInfo_,
  FileIdExtdDirectoryInfo_,
  FileIdExtdDirectoryRestartInfo_,
#endif
#if NTDDI_VERSION >= NTDDI_WIN10_RS1
  FileDispositionInfoEx_,
  FileRenameInfoEx_,
#endif
#if NTDDI_VERSION >= NTDDI_WIN10_19H1
  FileCaseSensitiveInfo_,
  FileNormalizedNameInfo_,
#endif
  MaximumFileInfoByHandleClass_
};
#endif

using OVERLAPPED_ = struct _OVERLAPPED {
  ULONG_PTR_ Internal;
  ULONG_PTR_ InternalHigh;
  WASMEDGE_WINAPI_DETAIL_EXTENSION union {
    WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
      DWORD_ Offset;
      DWORD_ OffsetHigh;
    };
    PVOID_ Pointer;
  };
  HANDLE_ hEvent;
};
using LPOVERLAPPED_ = OVERLAPPED_ *;

using LPOVERLAPPED_COMPLETION_ROUTINE_ = VOID_(WASMEDGE_WINAPI_WINAPI_CC *)(
    DWORD_ dwErrorCode, DWORD_ dwNumberOfBytesTransfered,
    LPOVERLAPPED_ lpOverlapped) noexcept;

static inline constexpr const DWORD_ ERROR_FILE_NOT_FOUND_ = 2;
static inline constexpr const DWORD_ ERROR_ACCESS_DENIED_ = 5;
static inline constexpr const DWORD_ ERROR_NOT_ENOUGH_MEMORY_ = 8;
static inline constexpr const DWORD_ ERROR_NO_MORE_FILES_ = 18;
static inline constexpr const DWORD_ ERROR_SHARING_VIOLATION_ = 32;
static inline constexpr const DWORD_ ERROR_FILE_EXISTS_ = 80;
static inline constexpr const DWORD_ ERROR_INVALID_PARAMETER_ = 87;
static inline constexpr const DWORD_ ERROR_INSUFFICIENT_BUFFER_ = 122;
static inline constexpr const DWORD_ ERROR_ALREADY_EXISTS_ = 183;
static inline constexpr const DWORD_ ERROR_PIPE_BUSY_ = 231;
static inline constexpr const DWORD_ ERROR_IO_PENDING_ = 997;
static inline constexpr const DWORD_ ERROR_INVALID_FLAGS_ = 1004;
static inline constexpr const DWORD_ ERROR_NO_UNICODE_TRANSLATION_ = 1113;

static inline const HANDLE_ INVALID_HANDLE_VALUE_ =
    reinterpret_cast<HANDLE_>(-1);

static inline constexpr const DWORD_ VOLUME_NAME_DOS_ = 0x0;
static inline constexpr const DWORD_ FILE_NAME_NORMALIZED_ = 0x0;

static inline constexpr const DWORD_ FILE_TYPE_CHAR_ = 0x2;
static inline constexpr const DWORD_ FILE_TYPE_PIPE_ = 0x3;

static inline constexpr const DWORD_ FILE_FLAG_WRITE_THROUGH_ = 0x80000000;
static inline constexpr const DWORD_ FILE_FLAG_OVERLAPPED_ = 0x40000000;
static inline constexpr const DWORD_ FILE_FLAG_NO_BUFFERING_ = 0x20000000;
static inline constexpr const DWORD_ FILE_FLAG_SEQUENTIAL_SCAN_ = 0x08000000;
static inline constexpr const DWORD_ FILE_FLAG_BACKUP_SEMANTICS_ = 0x02000000;
static inline constexpr const DWORD_ FILE_FLAG_OPEN_REPARSE_POINT_ = 0x00200000;
static inline constexpr const DWORD_ READ_CONTROL_ = 0x00020000;
static inline constexpr const DWORD_ SYNCHRONIZE_ = 0x00100000;
static inline constexpr const DWORD_ STANDARD_RIGHTS_READ_ = READ_CONTROL_;
static inline constexpr const DWORD_ STANDARD_RIGHTS_WRITE_ = READ_CONTROL_;
static inline constexpr const DWORD_ STANDARD_RIGHTS_EXECUTE_ = READ_CONTROL_;
static inline constexpr const DWORD_ GENERIC_READ_ = 0x80000000;
static inline constexpr const DWORD_ GENERIC_WRITE_ = 0x40000000;
static inline constexpr const DWORD_ FILE_READ_DATA_ = 0x0001;
static inline constexpr const DWORD_ FILE_WRITE_DATA_ = 0x0002;
static inline constexpr const DWORD_ FILE_APPEND_DATA_ = 0x0004;
static inline constexpr const DWORD_ FILE_READ_EA_ = 0x0008;
static inline constexpr const DWORD_ FILE_WRITE_EA_ = 0x0010;
static inline constexpr const DWORD_ FILE_EXECUTE_ = 0x0020;
static inline constexpr const DWORD_ FILE_READ_ATTRIBUTES_ = 0x0080;
static inline constexpr const DWORD_ FILE_WRITE_ATTRIBUTES_ = 0x0100;
static inline constexpr const DWORD_ FILE_GENERIC_READ_ =
    STANDARD_RIGHTS_READ_ | FILE_READ_DATA_ | FILE_READ_ATTRIBUTES_ |
    FILE_READ_EA_ | SYNCHRONIZE_;
static inline constexpr const DWORD_ FILE_GENERIC_WRITE_ =
    STANDARD_RIGHTS_WRITE_ | FILE_WRITE_DATA_ | FILE_WRITE_ATTRIBUTES_ |
    FILE_WRITE_EA_ | FILE_APPEND_DATA_ | SYNCHRONIZE_;
static inline constexpr const DWORD_ FILE_GENERIC_EXECUTE_ =
    STANDARD_RIGHTS_EXECUTE_ | FILE_EXECUTE_ | FILE_READ_ATTRIBUTES_ |
    SYNCHRONIZE_;

static inline constexpr const DWORD_ FILE_ATTRIBUTE_DIRECTORY_ = 0x00000010;
static inline constexpr const DWORD_ FILE_ATTRIBUTE_NORMAL_ = 0x00000080;
static inline constexpr const DWORD_ FILE_ATTRIBUTE_SPARSE_FILE_ = 0x00000200;
static inline constexpr const DWORD_ FILE_ATTRIBUTE_REPARSE_POINT_ = 0x00000400;

static inline constexpr const DWORD_ CREATE_NEW_ = 1;
static inline constexpr const DWORD_ CREATE_ALWAYS_ = 2;
static inline constexpr const DWORD_ OPEN_EXISTING_ = 3;
static inline constexpr const DWORD_ OPEN_ALWAYS_ = 4;
static inline constexpr const DWORD_ TRUNCATE_EXISTING_ = 5;

static inline constexpr const DWORD_ INVALID_FILE_ATTRIBUTES_ =
    static_cast<DWORD_>(-1);

static inline constexpr const DWORD_ FILE_SHARE_READ_ = 0x00000001;
static inline constexpr const DWORD_ FILE_SHARE_WRITE_ = 0x00000002;
static inline constexpr const DWORD_ FILE_SHARE_DELETE_ = 0x00000004;

static inline constexpr const DWORD_ FILE_BEGIN_ = 0;
static inline constexpr const DWORD_ FILE_CURRENT_ = 1;
static inline constexpr const DWORD_ FILE_END_ = 2;

static inline constexpr const DWORD_ FILE_MAP_READ_ = 0x00000004;

static inline constexpr const DWORD_ MOVEFILE_REPLACE_EXISTING_ = 0x00000001;

#if NTDDI_VERSION >= NTDDI_VISTA
static inline constexpr const DWORD_ SYMBOLIC_LINK_FLAG_DIRECTORY_ = 0x1;
#endif

static inline constexpr const DWORD_ STD_INPUT_HANDLE_ =
    static_cast<DWORD_>(-10);
static inline constexpr const DWORD_ STD_OUTPUT_HANDLE_ =
    static_cast<DWORD_>(-11);
static inline constexpr const DWORD_ STD_ERROR_HANDLE_ =
    static_cast<DWORD_>(-12);

} // namespace WasmEdge::winapi

extern "C" {

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
CancelIo(WasmEdge::winapi::HANDLE_ hFile);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
CloseHandle(WasmEdge::winapi::HANDLE_ hObject);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
CreateDirectoryW(WasmEdge::winapi::LPCWSTR_ lpPathName,
                 WasmEdge::winapi::LPSECURITY_ATTRIBUTES_ lpSecurityAttributes);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HANDLE_
    WASMEDGE_WINAPI_WINAPI_CC
    CreateFileMappingW(
        WasmEdge::winapi::HANDLE_ hFile,
        WasmEdge::winapi::LPSECURITY_ATTRIBUTES_ lpFileMappingAttributes,
        WasmEdge::winapi::DWORD_ flProtect,
        WasmEdge::winapi::DWORD_ dwMaximumSizeHigh,
        WasmEdge::winapi::DWORD_ dwMaximumSizeLow,
        WasmEdge::winapi::LPCWSTR_ lpName);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HANDLE_
    WASMEDGE_WINAPI_WINAPI_CC
    CreateFileW(WasmEdge::winapi::LPCWSTR_ lpFileName,
                WasmEdge::winapi::DWORD_ dwDesiredAccess,
                WasmEdge::winapi::DWORD_ dwShareMode,
                WasmEdge::winapi::LPSECURITY_ATTRIBUTES_ lpSecurityAttributes,
                WasmEdge::winapi::DWORD_ dwCreationDisposition,
                WasmEdge::winapi::DWORD_ dwFlagsAndAttributes,
                WasmEdge::winapi::HANDLE_ hTemplateFile);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
CreateHardLinkW(WasmEdge::winapi::LPCWSTR_ lpFileName,
                WasmEdge::winapi::LPCWSTR_ lpExistingFileName,
                WasmEdge::winapi::LPSECURITY_ATTRIBUTES_ lpSecurityAttributes);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
DeleteFileW(WasmEdge::winapi::LPCWSTR_ lpFileName);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
FindClose(WasmEdge::winapi::HANDLE_ hFindFile);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HANDLE_
    WASMEDGE_WINAPI_WINAPI_CC
    FindFirstFileW(WasmEdge::winapi::LPCWSTR_ lpFileName,
                   WasmEdge::winapi::LPWIN32_FIND_DATAW_ lpFindFileData);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
FindNextFileW(WasmEdge::winapi::HANDLE_ hFindFile,
              WasmEdge::winapi::LPWIN32_FIND_DATAW_ lpFindFileData);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
FlushFileBuffers(WasmEdge::winapi::HANDLE_ hFile);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::DWORD_ WASMEDGE_WINAPI_WINAPI_CC
GetFileAttributesW(WasmEdge::winapi::LPCWSTR_ lpFileName);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
GetFileInformationByHandle(
    WasmEdge::winapi::HANDLE_ hFile,
    WasmEdge::winapi::LPBY_HANDLE_FILE_INFORMATION_ lpFileInformation);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
GetFileSizeEx(WasmEdge::winapi::HANDLE_ hFile,
              WasmEdge::winapi::LARGE_INTEGER_ *lpFileSize);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::DWORD_ WASMEDGE_WINAPI_WINAPI_CC
GetFileType(WasmEdge::winapi::HANDLE_ hFile);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::DWORD_
    WASMEDGE_WINAPI_WINAPI_CC GetLastError(WasmEdge::winapi::VOID_);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
GetNamedPipeInfo(WasmEdge::winapi::HANDLE_ hNamedPipe,
                 WasmEdge::winapi::LPDWORD_ lpFlags,
                 WasmEdge::winapi::LPDWORD_ lpOutBufferSize,
                 WasmEdge::winapi::LPDWORD_ lpInBufferSize,
                 WasmEdge::winapi::LPDWORD_ lpMaxInstances);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
GetOverlappedResult(WasmEdge::winapi::HANDLE_ hFile,
                    WasmEdge::winapi::LPOVERLAPPED_ lpOverlapped,
                    WasmEdge::winapi::LPDWORD_ lpNumberOfBytesTransferred,
                    WasmEdge::winapi::BOOL_ bWait);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HANDLE_
    WASMEDGE_WINAPI_WINAPI_CC
    GetStdHandle(WasmEdge::winapi::DWORD_ nStdHandle);

WASMEDGE_WINAPI_SYMBOL_IMPORT
void WASMEDGE_WINAPI_WINAPI_CC
GetSystemTimeAsFileTime(WasmEdge::winapi::LPFILETIME_ lpSystemTimeAsFileTime);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::LPVOID_ WASMEDGE_WINAPI_WINAPI_CC
MapViewOfFile(WasmEdge::winapi::HANDLE_ hFileMappingObject,
              WasmEdge::winapi::DWORD_ dwDesiredAccess,
              WasmEdge::winapi::DWORD_ dwFileOffsetHigh,
              WasmEdge::winapi::DWORD_ dwFileOffsetLow,
              WasmEdge::winapi::SIZE_T_ dwNumberOfBytesToMap);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
MoveFileExW(WasmEdge::winapi::LPCWSTR_ lpExistingFileName,
            WasmEdge::winapi::LPCWSTR_ lpNewFileName,
            WasmEdge::winapi::DWORD_ dwFlags);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
QueryPerformanceFrequency(WasmEdge::winapi::LARGE_INTEGER_ *lpFrequency);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC ReadFileEx(
    WasmEdge::winapi::HANDLE_ hFile, WasmEdge::winapi::LPVOID_ lpBuffer,
    WasmEdge::winapi::DWORD_ nNumberOfBytesToRead,
    WasmEdge::winapi::LPOVERLAPPED_ lpOverlapped,
    WasmEdge::winapi::LPOVERLAPPED_COMPLETION_ROUTINE_ lpCompletionRoutine);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
RemoveDirectoryW(WasmEdge::winapi::LPCWSTR_ lpPathName);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
SetFilePointerEx(WasmEdge::winapi::HANDLE_ hFile,
                 WasmEdge::winapi::LARGE_INTEGER_ liDistanceToMove,
                 WasmEdge::winapi::LARGE_INTEGER_ *lpNewFilePointer,
                 WasmEdge::winapi::DWORD_ dwMoveMethod);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
SetFileTime(WasmEdge::winapi::HANDLE_ hFile,
            const WasmEdge::winapi::FILETIME_ *lpCreationTime,
            const WasmEdge::winapi::FILETIME_ *lpLastAccessTime,
            const WasmEdge::winapi::FILETIME_ *lpLastWriteTime);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_
    WASMEDGE_WINAPI_WINAPI_CC SwitchToThread(WasmEdge::winapi::VOID_);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
UnmapViewOfFile(WasmEdge::winapi::LPCVOID_ lpBaseAddress);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC WriteFileEx(
    WasmEdge::winapi::HANDLE_ hFile, WasmEdge::winapi::LPCVOID_ lpBuffer,
    WasmEdge::winapi::DWORD_ nNumberOfBytesToWrite,
    WasmEdge::winapi::LPOVERLAPPED_ lpOverlapped,
    WasmEdge::winapi::LPOVERLAPPED_COMPLETION_ROUTINE_ lpCompletionRoutine);

#if NTDDI_VERSION >= NTDDI_VISTA
WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOLEAN_
    WASMEDGE_WINAPI_WINAPI_CC
    CreateSymbolicLinkW(WasmEdge::winapi::LPCWSTR_ lpSymlinkFileName,
                        WasmEdge::winapi::LPCWSTR_ lpTargetFileName,
                        WasmEdge::winapi::DWORD_ dwFlags);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
GetFileInformationByHandleEx(
    WasmEdge::winapi::HANDLE_ hFile,
    WasmEdge::winapi::FILE_INFO_BY_HANDLE_CLASS_ FileInformationClass,
    WasmEdge::winapi::LPVOID_ lpFileInformation,
    WasmEdge::winapi::DWORD_ dwBufferSize);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::DWORD_ WASMEDGE_WINAPI_WINAPI_CC
GetFinalPathNameByHandleW(WasmEdge::winapi::HANDLE_ hFile,
                          WasmEdge::winapi::LPWSTR_ lpszFilePath,
                          WasmEdge::winapi::DWORD_ cchFilePath,
                          WasmEdge::winapi::DWORD_ dwFlags);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
SetFileInformationByHandle(
    WasmEdge::winapi::HANDLE_ hFile,
    WasmEdge::winapi::FILE_INFO_BY_HANDLE_CLASS_ FileInformationClass,
    WasmEdge::winapi::LPVOID_ lpFileInformation,
    WasmEdge::winapi::DWORD_ dwBufferSize);
#endif

#if NTDDI_VERSION >= NTDDI_WIN8
WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HANDLE_
    WASMEDGE_WINAPI_WINAPI_CC
    CreateFile2(
        WasmEdge::winapi::LPCWSTR_ lpFileName,
        WasmEdge::winapi::DWORD_ dwDesiredAccess,
        WasmEdge::winapi::DWORD_ dwShareMode,
        WasmEdge::winapi::DWORD_ dwCreationDisposition,
        WasmEdge::winapi::LPCREATEFILE2_EXTENDED_PARAMETERS_ pCreateExParams);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::HANDLE_ WASMEDGE_WINAPI_WINAPI_CC CreateFileMappingFromApp(
    WasmEdge::winapi::HANDLE_ hFile,
    WasmEdge::winapi::PSECURITY_ATTRIBUTES_ SecurityAttributes,
    WasmEdge::winapi::ULONG_ PageProtection,
    WasmEdge::winapi::ULONG64_ MaximumSize, WasmEdge::winapi::PCWSTR_ Name);

WASMEDGE_WINAPI_SYMBOL_IMPORT
void WASMEDGE_WINAPI_WINAPI_CC GetSystemTimePreciseAsFileTime(
    WasmEdge::winapi::LPFILETIME_ lpSystemTimeAsFileTime);

WASMEDGE_WINAPI_SYMBOL_IMPORT
WasmEdge::winapi::PVOID_ WASMEDGE_WINAPI_WINAPI_CC
MapViewOfFileFromApp(WasmEdge::winapi::HANDLE_ hFileMappingObject,
                     WasmEdge::winapi::ULONG_ DesiredAccess,
                     WasmEdge::winapi::ULONG64_ FileOffset,
                     WasmEdge::winapi::SIZE_T_ NumberOfBytesToMap);
#endif

} // extern "C"

namespace WasmEdge::winapi {
using ::CancelIo;
using ::CloseHandle;
using ::CreateDirectoryW;
using ::CreateFileMappingW;
using ::CreateFileW;
using ::CreateHardLinkW;
using ::DeleteFileW;
using ::FindClose;
using ::FindFirstFileW;
using ::FindNextFileW;
using ::FlushFileBuffers;
using ::GetFileAttributesW;
using ::GetFileInformationByHandle;
using ::GetFileSizeEx;
using ::GetFileType;
using ::GetLastError;
using ::GetNamedPipeInfo;
using ::GetOverlappedResult;
using ::GetStdHandle;
using ::GetSystemTimeAsFileTime;
using ::MapViewOfFile;
using ::MoveFileExW;
using ::QueryPerformanceFrequency;
using ::ReadFileEx;
using ::RemoveDirectoryW;
using ::SetFilePointerEx;
using ::SetFileTime;
using ::SwitchToThread;
using ::UnmapViewOfFile;
using ::WriteFileEx;

#if NTDDI_VERSION >= NTDDI_VISTA
using ::CreateSymbolicLinkW;
using ::GetFileInformationByHandleEx;
using ::GetFinalPathNameByHandleW;
using ::SetFileInformationByHandle;
#endif

#if NTDDI_VERSION >= NTDDI_WIN8
using ::CreateFile2;
using ::CreateFileMappingFromApp;
using ::GetSystemTimePreciseAsFileTime;
using ::MapViewOfFileFromApp;
#endif

} // namespace WasmEdge::winapi

namespace WasmEdge::winapi {
using HLOCAL_ = HANDLE_;
using HMODULE_ = void *;

#ifdef _WIN64
using FARPROC_ = INT_PTR_(WASMEDGE_WINAPI_WINAPI_CC *)();
using NEARPROC_ = INT_PTR_(WASMEDGE_WINAPI_WINAPI_CC *)();
using PROC_ = INT_PTR_(WASMEDGE_WINAPI_WINAPI_CC *)();
#else
using FARPROC_ = int(WASMEDGE_WINAPI_WINAPI_CC *)();
using NEARPROC_ = int(WASMEDGE_WINAPI_WINAPI_CC *)();
using PROC_ = int(WASMEDGE_WINAPI_WINAPI_CC *)();
#endif

using RUNTIME_FUNCTION_ = struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
  DWORD_ BeginAddress;
  DWORD_ EndAddress;
  union {
    DWORD_ UnwindInfoAddress;
    DWORD_ UnwindData;
  } DUMMYUNIONNAME;
};
using PRUNTIME_FUNCTION_ = RUNTIME_FUNCTION_ *;

static inline constexpr const DWORD_ FORMAT_MESSAGE_ALLOCATE_BUFFER_ =
    0x00000100;
static inline constexpr const DWORD_ FORMAT_MESSAGE_IGNORE_INSERTS_ =
    0x00000200;
static inline constexpr const DWORD_ FORMAT_MESSAGE_FROM_SYSTEM_ = 0x00001000;
static inline constexpr const WORD_ LANG_NEUTRAL_ = 0x00;
static inline constexpr const WORD_ SUBLANG_DEFAULT_ = 0x01;

WASMEDGE_WINAPI_FORCEINLINE inline constexpr WORD_
MAKELANGID_(WORD_ p, WORD_ s) noexcept {
  return static_cast<WORD_>((static_cast<WORD_>(s) << 10) |
                            static_cast<WORD_>(p));
}

} // namespace WasmEdge::winapi

extern "C" {

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::DWORD_ WASMEDGE_WINAPI_WINAPI_CC
FormatMessageA(WasmEdge::winapi::DWORD_ dwFlags,
               WasmEdge::winapi::LPCVOID_ lpSource,
               WasmEdge::winapi::DWORD_ dwMessageId,
               WasmEdge::winapi::DWORD_ dwLanguageId,
               WasmEdge::winapi::LPSTR_ lpBuffer,
               WasmEdge::winapi::DWORD_ nSize, va_list *Arguments);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
FreeLibrary(WasmEdge::winapi::HMODULE_ hModule);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::FARPROC_
    WASMEDGE_WINAPI_WINAPI_CC
    GetProcAddress(WasmEdge::winapi::HMODULE_ hModule,
                   WasmEdge::winapi::LPCSTR_ lpProcName);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HMODULE_
    WASMEDGE_WINAPI_WINAPI_CC
    LoadLibraryExW(WasmEdge::winapi::LPCWSTR_ lpFileName,
                   WasmEdge::winapi::HANDLE_ hFile,
                   WasmEdge::winapi::DWORD_ dwFlags);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOLEAN_
    WASMEDGE_WINAPI_WINAPI_CC
    RtlAddFunctionTable(WasmEdge::winapi::PRUNTIME_FUNCTION_ FunctionTable,
                        WasmEdge::winapi::ULONG_ EntryCount,
                        WasmEdge::winapi::ULONG_PTR_ BaseAddress);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOLEAN_
    WASMEDGE_WINAPI_WINAPI_CC
    RtlDeleteFunctionTable(WasmEdge::winapi::PRUNTIME_FUNCTION_ FunctionTable);

} // extern "C"

namespace WasmEdge::winapi {
using ::FormatMessageA;
using ::FreeLibrary;
using ::GetProcAddress;
using ::LoadLibraryExW;
using ::RtlAddFunctionTable;
using ::RtlDeleteFunctionTable;
} // namespace WasmEdge::winapi

namespace WasmEdge::winapi {
using HWND_ = void *;
using HRESULT_ = LONG_;
using GUID_ = struct _GUID {
  ULONG_ Data1;
  unsigned short Data2;
  unsigned short Data3;
  unsigned char Data4[8];
};
using KNOWNFOLDERID_ = GUID_;
using REFKNOWNFOLDERID_ = const KNOWNFOLDERID_ &;

static inline constexpr const int CSIDL_PROFILE_ = 0x0028;
static inline constexpr const int CSIDL_LOCAL_APPDATA_ = 0x001c;
static inline constexpr const int CSIDL_FLAG_CREATE_ = 0x8000;

static inline constexpr const int KF_FLAG_CREATE_ = 0x00008000;

WASMEDGE_WINAPI_FORCEINLINE inline constexpr bool
SUCCEEDED_(HRESULT_ Stat) noexcept {
  return Stat >= 0;
}

} // namespace WasmEdge::winapi

extern "C" {

extern const WasmEdge::winapi::GUID_ FOLDERID_Profile;
extern const WasmEdge::winapi::GUID_ FOLDERID_LocalAppData;

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HRESULT_
    WASMEDGE_WINAPI_WINAPI_CC
    SHGetFolderPathW(WasmEdge::winapi::HWND_ hwnd, int csidl,
                     WasmEdge::winapi::HANDLE_ hToken,
                     WasmEdge::winapi::DWORD_ dwFlags,
                     WasmEdge::winapi::LPSTR_ pszPath);

#if NTDDI_VERSION >= NTDDI_VISTA
WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HRESULT_
    WASMEDGE_WINAPI_WINAPI_CC
    SHGetKnownFolderPath(WasmEdge::winapi::REFKNOWNFOLDERID_ rfid,
                         WasmEdge::winapi::DWORD_ dwFlags,
                         WasmEdge::winapi::HANDLE_ hToken,
                         WasmEdge::winapi::PWSTR_ *ppszPath);
#endif

} // extern "C"

namespace WasmEdge::winapi {
using ::FOLDERID_LocalAppData;
using ::FOLDERID_Profile;
using ::SHGetFolderPathW;

#if NTDDI_VERSION >= NTDDI_VISTA
using ::SHGetKnownFolderPath;
#endif
} // namespace WasmEdge::winapi

namespace WasmEdge::winapi {
static inline constexpr const DWORD_ MEM_COMMIT_ = 0x00001000;
static inline constexpr const DWORD_ MEM_RESERVE_ = 0x00002000;
static inline constexpr const DWORD_ MEM_RELEASE_ = 0x00008000;

static inline constexpr const DWORD_ PAGE_NOACCESS_ = 0x01;
static inline constexpr const DWORD_ PAGE_READONLY_ = 0x02;
static inline constexpr const DWORD_ PAGE_READWRITE_ = 0x04;
static inline constexpr const DWORD_ PAGE_EXECUTE_READ_ = 0x20;
} // namespace WasmEdge::winapi

extern "C" {

WASMEDGE_WINAPI_SYMBOL_IMPORT void WASMEDGE_WINAPI_WINAPI_CC
CoTaskMemFree(WasmEdge::winapi::LPVOID_ pv);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::HLOCAL_
    WASMEDGE_WINAPI_WINAPI_CC
    LocalFree(WasmEdge::winapi::HLOCAL_ hMem);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::LPVOID_
    WASMEDGE_WINAPI_WINAPI_CC
    VirtualAlloc(WasmEdge::winapi::LPVOID_ lpAddress,
                 WasmEdge::winapi::SIZE_T_ dwSize,
                 WasmEdge::winapi::DWORD_ flAllocationType,
                 WasmEdge::winapi::DWORD_ flProtect);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
VirtualFree(WasmEdge::winapi::LPVOID_ lpAddress,
            WasmEdge::winapi::SIZE_T_ dwSize,
            WasmEdge::winapi::DWORD_ dwFreeType);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::BOOL_ WASMEDGE_WINAPI_WINAPI_CC
VirtualProtect(WasmEdge::winapi::LPVOID_ lpAddress,
               WasmEdge::winapi::SIZE_T_ dwSize,
               WasmEdge::winapi::DWORD_ flNewProtect,
               WasmEdge::winapi::PDWORD_ lpflOldProtect);

} // extern "C"

namespace WasmEdge::winapi {
using ::CoTaskMemFree;
using ::LocalFree;
using ::VirtualAlloc;
using ::VirtualFree;
using ::VirtualProtect;
} // namespace WasmEdge::winapi

namespace WasmEdge::winapi {

static inline constexpr const DWORD_ EXCEPTION_MAXIMUM_PARAMETERS_ = 15;
static inline constexpr const DWORD_ EXCEPTION_ACCESS_VIOLATION_ = 0xC0000005L;
static inline constexpr const DWORD_ EXCEPTION_INT_DIVIDE_BY_ZERO_ =
    0xC0000094L;
static inline constexpr const DWORD_ EXCEPTION_INT_OVERFLOW_ = 0xC0000095L;
static inline constexpr const LONG_ EXCEPTION_CONTINUE_EXECUTION_ =
    static_cast<LONG_>(0xffffffff);

using CONTEXT_ = struct _CONTEXT;
using PCONTEXT_ = CONTEXT_ *;

using EXCEPTION_RECORD_ = struct _EXCEPTION_RECORD {
  DWORD_ ExceptionCode;
  DWORD_ ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID_ ExceptionAddress;
  DWORD_ NumberParameters;
  PULONG_ ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS_];
};
using PEXCEPTION_RECORD_ = EXCEPTION_RECORD_ *;

using EXCEPTION_POINTERS_ = struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD_ ExceptionRecord;
  PCONTEXT_ ContextRecord;
};
using PEXCEPTION_POINTERS_ = EXCEPTION_POINTERS_ *;

using PVECTORED_EXCEPTION_HANDLER_ =
    LONG_(WASMEDGE_WINAPI_WINAPI_CC *)(PEXCEPTION_POINTERS_ ExceptionInfo);

} // namespace WasmEdge::winapi

extern "C" {
WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::PVOID_ WASMEDGE_WINAPI_WINAPI_CC
AddVectoredExceptionHandler(
    WasmEdge::winapi::ULONG_ First,
    WasmEdge::winapi::PVECTORED_EXCEPTION_HANDLER_ Handler);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::ULONG_ WASMEDGE_WINAPI_WINAPI_CC
RemoveVectoredExceptionHandler(WasmEdge::winapi::PVOID_ Handle);
} // extern "C"

namespace WasmEdge::winapi {
using ::AddVectoredExceptionHandler;
using ::RemoveVectoredExceptionHandler;
} // namespace WasmEdge::winapi

namespace WasmEdge::winapi {
using u_char = unsigned char;
using u_short = unsigned short;
using u_int = unsigned int;
using u_long = unsigned long;
using u_int64 = unsigned long long;
using socklen_t = int;

using SOCKET_ = UINT_PTR_;
using ADDRESS_FAMILY_ = u_short;
static inline constexpr const SOCKET_ INVALID_SOCKET_ =
    static_cast<SOCKET_>(~0);
static inline constexpr const int SOCKET_ERROR_ = -1;

static inline constexpr const size_t WSADESCRIPTION_LEN_ = 256;
static inline constexpr const size_t WSASYS_STATUS_LEN_ = 128;
using WSADATA_ = struct WSAData {
  WORD_ wVersion;
  WORD_ wHighVersion;
#ifdef _WIN64
  u_short iMaxSockets;
  u_short iMaxUdpDg;
  char *lpVendorInfo;
  char szDescription[WSADESCRIPTION_LEN_ + 1];
  char szSystemStatus[WSASYS_STATUS_LEN_ + 1];
#else
  char szDescription[WSADESCRIPTION_LEN_ + 1];
  char szSystemStatus[WSASYS_STATUS_LEN_ + 1];
  u_short iMaxSockets;
  u_short iMaxUdpDg;
  char *lpVendorInfo;
#endif
};
using LPWSADATA_ = WSADATA_ *;

using IN_ADDR_ = struct in_addr {
  WASMEDGE_WINAPI_DETAIL_EXTENSION union {
    WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
      u_char s_b1;
      u_char s_b2;
      u_char s_b3;
      u_char s_b4;
    } S_un_b;
    WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
      u_short s_w1;
      u_short s_w2;
    } S_un_w;
    u_long S_addr;
  } S_un;
};
#define s_addr S_un.S_addr
#define s_host S_un.S_un_b.s_b2
#define s_net S_un.S_un_b.s_b1
#define s_imp S_un.S_un_w.s_w2
#define s_impno S_un.S_un_b.s_b4
#define s_lh S_un.S_un_b.s_b3

using IN6_ADDR_ = struct in6_addr {
  WASMEDGE_WINAPI_DETAIL_EXTENSION union {
    u_char Byte[16];
    u_short Word[8];
  } u;
};
#define _S6_un u
#define _S6_u8 Byte
#define s6_addr _S6_un._S6_u8
#define s6_bytes u.Byte
#define s6_words u.Word

using SOCKADDR_ = struct sockaddr {
  ADDRESS_FAMILY_ sa_family;
  CHAR_ sa_data[14];
};

using SOCKADDR_IN_ = struct sockaddr_in {
  ADDRESS_FAMILY_ sin_family;
  u_short sin_port;
  IN_ADDR_ sin_addr;
  CHAR_ sin_zero[8];
};

using SCOPE_ID_ = struct _SCOPE_ID {
  WASMEDGE_WINAPI_DETAIL_EXTENSION union {
    WASMEDGE_WINAPI_DETAIL_EXTENSION struct {
      u_long Zone : 28;
      u_long Level : 4;
    };
    u_long Value;
  };
};

using SOCKADDR_IN6_LH_ = struct sockaddr_in6 {
  ADDRESS_FAMILY_ sin6_family;
  u_short sin6_port;
  u_long sin6_flowinfo;
  IN6_ADDR_ sin6_addr;
  WASMEDGE_WINAPI_DETAIL_EXTENSION union {
    u_long sin6_scope_id;
    SCOPE_ID_ sin6_scope_struct;
  };
};

static inline constexpr const size_t _SS_MAXSIZE = 128;
static inline constexpr const size_t _SS_ALIGNSIZE = 8;
static inline constexpr const size_t _SS_PAD1SIZE =
    _SS_ALIGNSIZE - sizeof(ADDRESS_FAMILY_);
static inline constexpr const size_t _SS_PAD2SIZE =
    _SS_MAXSIZE - sizeof(ADDRESS_FAMILY_) - _SS_PAD1SIZE - _SS_ALIGNSIZE;
using SOCKADDR_STORAGE_LH = struct sockaddr_storage {
  ADDRESS_FAMILY_ ss_family;
  CHAR_ __ss_pad1[_SS_PAD1SIZE];
  LONGLONG_ __ss_align;
  CHAR_ __ss_pad2[_SS_PAD2SIZE];
};

using ADDRINFOA_ = struct addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  size_t ai_addrlen;
  char *ai_canonname;
  struct sockaddr *ai_addr;
  struct addrinfo *ai_next;
};
using PADDRINFOA_ = ADDRINFOA_ *;

static inline constexpr const int AI_PASSIVE = 0x00000001;
static inline constexpr const int AI_CANONNAME = 0x00000002;
static inline constexpr const int AI_NUMERICHOST = 0x00000004;
#if NTDDI_VERSION >= NTDDI_VISTA
static inline constexpr const int AI_NUMERICSERV = 0x00000008;
static inline constexpr const int AI_ALL = 0x00000100;
static inline constexpr const int AI_ADDRCONFIG = 0x00000400;
static inline constexpr const int AI_V4MAPPED = 0x00000800;
#endif

static inline constexpr const long IOCPARM_MASK = 0x7f;
static inline constexpr const long IOC_IN = static_cast<long>(0x80000000);
static inline constexpr long _IOW(long X, long Y) noexcept {
  return IOC_IN | ((static_cast<long>(sizeof(u_long)) & IOCPARM_MASK) << 16) |
         (X << 8) | Y;
}
static inline constexpr const long FIONBIO = _IOW('f', 126);

static inline constexpr const int IPPROTO_IP = 0;
static inline constexpr const int IPPROTO_TCP = 6;
static inline constexpr const int IPPROTO_UDP = 17;

static inline constexpr const u_long INADDR_ANY = 0x00000000;
static inline constexpr const u_long INADDR_LOOPBACK = 0x7f000001;

static inline constexpr const int SOCK_STREAM = 1;
static inline constexpr const int SOCK_DGRAM = 2;

static inline constexpr const int SO_ACCEPTCONN = 0x0002;
static inline constexpr const int SO_REUSEADDR = 0x0004;
static inline constexpr const int SO_KEEPALIVE = 0x0008;
static inline constexpr const int SO_DONTROUTE = 0x0010;
static inline constexpr const int SO_BROADCAST = 0x0020;
static inline constexpr const int SO_LINGER = 0x0080;
static inline constexpr const int SO_OOBINLINE = 0x0100;

static inline constexpr const int SO_SNDBUF = 0x1001;
static inline constexpr const int SO_RCVBUF = 0x1002;
static inline constexpr const int SO_RCVLOWAT = 0x1004;
static inline constexpr const int SO_SNDTIMEO = 0x1005;
static inline constexpr const int SO_RCVTIMEO = 0x1006;
static inline constexpr const int SO_ERROR = 0x1007;
static inline constexpr const int SO_TYPE = 0x1008;

static inline constexpr const int AF_UNSPEC = 0;
static inline constexpr const int AF_INET = 2;
static inline constexpr const int AF_INET6 = 23;

static inline constexpr const int SOL_SOCKET = 0xffff;

static inline constexpr const int MSG_PEEK = 0x2;
#if NTDDI_VERSION >= NTDDI_WS03
static inline constexpr const int MSG_WAITALL = 0x8;
#endif

static inline constexpr const int SD_RECEIVE = 0x0;
static inline constexpr const int SD_SEND = 0x1;
static inline constexpr const int SD_BOTH = 0x2;

static inline constexpr const DWORD_ WSABASEERR_ = 10000;
static inline constexpr const DWORD_ WSAEINTR_ = WSABASEERR_ + 4;
static inline constexpr const DWORD_ WSAEFAULT_ = WSABASEERR_ + 14;
static inline constexpr const DWORD_ WSAEINVAL_ = WSABASEERR_ + 22;
static inline constexpr const DWORD_ WSAEMFILE_ = WSABASEERR_ + 24;
static inline constexpr const DWORD_ WSAEWOULDBLOCK_ = WSABASEERR_ + 35;
static inline constexpr const DWORD_ WSAEINPROGRESS_ = WSABASEERR_ + 36;
static inline constexpr const DWORD_ WSAENOTSOCK_ = WSABASEERR_ + 38;
static inline constexpr const DWORD_ WSAEPROTOTYPE_ = WSABASEERR_ + 41;
static inline constexpr const DWORD_ WSAEPROTONOSUPPORT_ = WSABASEERR_ + 43;
static inline constexpr const DWORD_ WSAESOCKTNOSUPPORT_ = WSABASEERR_ + 44;
static inline constexpr const DWORD_ WSAEAFNOSUPPORT_ = WSABASEERR_ + 47;
static inline constexpr const DWORD_ WSAENETDOWN_ = WSABASEERR_ + 50;
static inline constexpr const DWORD_ WSAENOBUFS_ = WSABASEERR_ + 55;
static inline constexpr const DWORD_ WSAEPROCLIM_ = WSABASEERR_ + 67;
static inline constexpr const DWORD_ WSASYSNOTREADY_ = WSABASEERR_ + 91;
static inline constexpr const DWORD_ WSAVERNOTSUPPORTED_ = WSABASEERR_ + 92;
static inline constexpr const DWORD_ WSANOTINITIALISED_ = WSABASEERR_ + 93;
static inline constexpr const DWORD_ WSAEINVALIDPROCTABLE_ = WSABASEERR_ + 104;
static inline constexpr const DWORD_ WSAEINVALIDPROVIDER_ = WSABASEERR_ + 105;
static inline constexpr const DWORD_ WSAEPROVIDERFAILEDINIT_ =
    WSABASEERR_ + 106;
static inline constexpr const DWORD_ WSATYPE_NOT_FOUND_ = WSABASEERR_ + 109;
static inline constexpr const DWORD_ WSAHOST_NOT_FOUND_ = WSABASEERR_ + 1001;
static inline constexpr const DWORD_ WSATRY_AGAIN_ = WSABASEERR_ + 1002;
static inline constexpr const DWORD_ WSANO_RECOVERY_ = WSABASEERR_ + 1003;
} // namespace WasmEdge::winapi

extern "C" {

extern const WasmEdge::winapi::IN6_ADDR_ in6addr_loopback;

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::SOCKET_
    WASMEDGE_WINAPI_WINAPI_CC
    accept(WasmEdge::winapi::SOCKET_ s, struct WasmEdge::winapi::sockaddr *addr,
           WasmEdge::winapi::socklen_t *addrlen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
bind(WasmEdge::winapi::SOCKET_ s, const struct WasmEdge::winapi::sockaddr *addr,
     WasmEdge::winapi::socklen_t namelen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
closesocket(WasmEdge::winapi::SOCKET_ s);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC connect(
    WasmEdge::winapi::SOCKET_ s, const struct WasmEdge::winapi::sockaddr *name,
    WasmEdge::winapi::socklen_t namelen);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::VOID_ WASMEDGE_WINAPI_WINAPI_CC
freeaddrinfo(WasmEdge::winapi::PADDRINFOA_ pAddrInfo);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC getaddrinfo(
    WasmEdge::winapi::PCSTR_ pNodeName, WasmEdge::winapi::PCSTR_ pServiceName,
    const WasmEdge::winapi::ADDRINFOA_ *pHints,
    WasmEdge::winapi::PADDRINFOA_ *ppResult);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC getpeername(
    WasmEdge::winapi::SOCKET_ s, struct WasmEdge::winapi::sockaddr *name,
    WasmEdge::winapi::socklen_t *namelen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC getsockname(
    WasmEdge::winapi::SOCKET_ s, struct WasmEdge::winapi::sockaddr *name,
    WasmEdge::winapi::socklen_t *namelen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
getsockopt(WasmEdge::winapi::SOCKET_ s, int level, int optname, char *optval,
           WasmEdge::winapi::socklen_t *optlen);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::u_long WASMEDGE_WINAPI_WINAPI_CC
htonl(WasmEdge::winapi::u_long hostlong);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::u_short
    WASMEDGE_WINAPI_WINAPI_CC
    htons(WasmEdge::winapi::u_short hostshort);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC ioctlsocket(
    WasmEdge::winapi::SOCKET_ s, long cmd, WasmEdge::winapi::u_long *argp);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
listen(WasmEdge::winapi::SOCKET_ s, int backlog);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::u_short
    WASMEDGE_WINAPI_WINAPI_CC
    ntohs(WasmEdge::winapi::u_short netshort);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
recvfrom(WasmEdge::winapi::SOCKET_ s, char *buf, int len, int flags,
         struct WasmEdge::winapi::sockaddr *from,
         WasmEdge::winapi::socklen_t *fromlen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
sendto(WasmEdge::winapi::SOCKET_ s, const char *buf, int len, int flags,
       const struct WasmEdge::winapi::sockaddr *to,
       WasmEdge::winapi::socklen_t tolen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
setsockopt(WasmEdge::winapi::SOCKET_ s, int level, int optname,
           const char *optval, WasmEdge::winapi::socklen_t optlen);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
shutdown(WasmEdge::winapi::SOCKET_ s, int how);

WASMEDGE_WINAPI_SYMBOL_IMPORT WasmEdge::winapi::SOCKET_
    WASMEDGE_WINAPI_WINAPI_CC
    socket(int af, int type, int protocol);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC WSACleanup(void);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
WSAGetLastError(void);

WASMEDGE_WINAPI_SYMBOL_IMPORT int WASMEDGE_WINAPI_WINAPI_CC
WSAStartup(WasmEdge::winapi::WORD_ wVersionRequested,
           WasmEdge::winapi::LPWSADATA_ lpWSAData);

} // extern "C"

namespace WasmEdge::winapi {
using ::accept;
using ::bind;
using ::closesocket;
using ::connect;
using ::freeaddrinfo;
using ::getaddrinfo;
using ::getpeername;
using ::getsockname;
using ::getsockopt;
using ::htonl;
using ::htons;
using ::ioctlsocket;
using ::listen;
using ::ntohs;
using ::recvfrom;
using ::sendto;
using ::setsockopt;
using ::shutdown;
using ::socket;
using ::WSACleanup;
using ::WSAGetLastError;
using ::WSAStartup;
} // namespace WasmEdge::winapi

#endif
