// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

#include "common/defines.h"
#if WASMEDGE_OS_WINDOWS

#include "common/errcode.h"
#include "host/wasi/environ.h"
#include "host/wasi/inode.h"
#include "host/wasi/vfs.h"
#include "win.h"
#include <algorithm>
#include <new>
#include <numeric>
#include <vector>

namespace WasmEdge {
namespace Host {
namespace WASI {

// clang-format off
  /*

  ## Implementation Status

  ### Host Functions: Function-wise Summary

  | Function               | Status             | Comment                                                                                                                                                                                                                                                          |
  | ---------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `open`                 | complete           | some flags may not have an equivalent                                                                                                                                                                                                                            |
  | `fdAdvise`             | no equivalent      | have to find an solution                                                                                                                                                                                                                                         |
  | `fdAllocate`           | complete           | None                                                                                                                                                                                                                                                             |
  | `fdDatasync`           | complete           | documentation is not clear on whether metadata is also flushed, refer [here](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers#remarks)                                                                                     |
  | `fdFdstatGet`          | complete           | depends on a partially complete function - `fromFileType` (this function has been implemented partially in linux), find appropriate functions to query the equivalent flags and fill the other fields (the implementation for linux has not filled these fields) |
  | `fdFdstatSetFlags`     | complete           | depends on a partially complete function - `fromFileType` and an equivalent for device ID needs to be found which may be related to the file index                                                                                                               |
  | `fdFilestatSetSize`    | complete           | None                                                                                                                                                                                                                                                             |
  | `fdFilestatSetTimes`   | complete           | None                                                                                                                                                                                                                                                             |
  | `fdPread`              | complete           | there maybe issues due to casting                                                                                                                                                                                                                                |
  | `fdPwrite`             | complete           | there maybe issues due to casting                                                                                                                                                                                                                                |
  | `fdRead`               | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `fdWrite`              | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `fdReaddir`            | complete           | Need to optimise the function and it depends on a partially implemented function - `fromFileType`                                                                                                                                                                |
  | `fdSeek`               | complete           | None                                                                                                                                                                                                                                                             |
  | `fdSync`               | complete           | works when the file has been opened with the flags `FILE_FLAG_NO_BUFFERING` and `FILE_FLAG_WRITE_THROUGH` which I suspect is the desired behaviour, refer [here](https://devblogs.microsoft.com/oldnewthing/20210729-00/?p=105494)                               |
  | `fdTell`               | complete           | None                                                                                                                                                                                                                                                             |
  | `getNativeHandler`     | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `pathCreateDirectory`  | complete           | None                                                                                                                                                                                                                                                             |
  | `pathFilestatGet`      | complete           | similar to `stat` which uses absolute paths                                                                                                                                                                                                                      |
  | `pathFilestatSetTimes` | complete           | None                                                                                                                                                                                                                                                             |
  | `pathLink`             | complete           | None                                                                                                                                                                                                                                                             |
  | `pathOpen`             | complete           | None                                                                                                                                                                                                                                                             |
  | `pathReadlink`         | complete           | None                                                                                                                                                                                                                                                             |
  | `pathRemoveDirectory`  | complete           | had been already implemented                                                                                                                                                                                                                                     |
  | `pathRename`           | complete           | None                                                                                                                                                                                                                                                             |
  | `pathSymlink`          | complete           | None                                                                                                                                                                                                                                                             |
  | `pathUnlinkFile`       | complete           | None                                                                                                                                                                                                                                                             |
  | `pollOneoff`           | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `sockGetPeerAddr`      | incomplete         | behaviour is unspecified                                                                                                                                                                                                                                         |
  | `unsafeFiletype`       | partially complete | need to find equivalent flags for three file types                                                                                                                                                                                                               |
  | `filetype`             | partially complete | need to find equivalent flags for three file types                                                                                                                                                                                                               |
  | `isDirectory`          | complete           | None                                                                                                                                                                                                                                                             |
  | `isSymlink`            | complete           | None                                                                                                                                                                                                                                                             |
  | `filesize`             | complete           | None                                                                                                                                                                                                                                                             |
  | `canBrowse`            | incomplete         | need to find appropriate functions                                                                                                                                                                                                                               |
  | `Poller::clock`        | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::read`         | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::write`        | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::wait`         | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |

  Resolves #1227 and #1477

  Reference: https://github.com/WasmEdge/WasmEdge/issues/1477

  */
// clang-format on

namespace {

namespace winapi = WasmEdge::winapi;

inline constexpr uint64_t combineHighLow(uint32_t HighPart,
                                         uint32_t LowPart) noexcept {
  const winapi::ULARGE_INTEGER_ Temp = {.LowPart = LowPart,
                                        .HighPart = HighPart};
  return Temp.QuadPart;
}

inline constexpr __wasi_size_t calculateAddrinfoLinkedListSize(
    struct winapi::addrinfo *const Addrinfo) noexcept {
  __wasi_size_t Length = 0;
  for (struct winapi::addrinfo *TmpPointer = Addrinfo; TmpPointer != nullptr;
       TmpPointer = TmpPointer->ai_next) {
    Length++;
  }
  return Length;
};

inline bool isSocket(winapi::LPVOID_ H) noexcept {
  if (likely(winapi::GetFileType(H) != winapi::FILE_TYPE_PIPE_)) {
    return false;
  }
  return !winapi::GetNamedPipeInfo(H, nullptr, nullptr, nullptr, nullptr);
}

inline winapi::SOCKET_ toSocket(winapi::HANDLE_ H) noexcept {
  return reinterpret_cast<winapi::SOCKET_>(H);
}

inline winapi::HANDLE_ toHandle(winapi::SOCKET_ S) noexcept {
  return reinterpret_cast<winapi::HANDLE_>(S);
}

union UniversalAddress {
  struct {
    __wasi_address_family_t AddressFamily;
    uint8_t Address[128 - sizeof(__wasi_address_family_t)];
  };
  uint8_t Buffer[128];
};
static_assert(sizeof(UniversalAddress) == 128);

WasiExpect<std::pair<int, uint8_t *>>
resolveAddressFamilyAndAddress(uint8_t *AddressBuf,
                               uint8_t AddressLength) noexcept {
  if (AddressLength != sizeof(UniversalAddress)) {
    // Fallback
    switch (AddressLength) {
    case 4:
      return std::pair{winapi::AF_INET, AddressBuf};
    case 16:
      return std::pair{winapi::AF_INET6, AddressBuf};
    default:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    }
  }
  auto *UA = reinterpret_cast<UniversalAddress *>(AddressBuf);
  return std::pair{UA->AddressFamily, UA->Address};
}

std::pair<const char *, std::unique_ptr<char[]>>
createNullTerminatedString(std::string_view View) noexcept {
  const char *CStr = nullptr;
  std::unique_ptr<char[]> Buffer;
  if (!View.empty()) {
    if (const auto Pos = View.find_first_of('\0');
        Pos != std::string_view::npos) {
      CStr = View.data();
    } else {
      Buffer = std::make_unique<char[]>(View.size() + 1);
      std::copy(View.begin(), View.end(), Buffer.get());
      CStr = Buffer.get();
    }
  }
  return {CStr, std::move(Buffer)};
}

inline constexpr WasiExpect<winapi::DWORD_> toWhence(__wasi_whence_t Whence) {
  switch (Whence) {
  case __WASI_WHENCE_SET:
    return winapi::FILE_BEGIN_;
  case __WASI_WHENCE_END:
    return winapi::FILE_END_;
  case __WASI_WHENCE_CUR:
    return winapi::FILE_CURRENT_;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
}

WasiExpect<std::tuple<
    winapi::DWORD_, winapi::DWORD_,
    winapi::DWORD_>> inline constexpr getOpenFlags(__wasi_oflags_t OpenFlags,
                                                   __wasi_fdflags_t FdFlags,
                                                   uint8_t VFSFlags) noexcept {
  winapi::DWORD_ AttributeFlags = winapi::FILE_ATTRIBUTE_NORMAL_;
  if (FdFlags & __WASI_FDFLAGS_NONBLOCK) {
    AttributeFlags |= winapi::FILE_FLAG_OVERLAPPED_;
    FdFlags &= ~__WASI_FDFLAGS_NONBLOCK;
  }
  // Source: https://devblogs.microsoft.com/oldnewthing/20210729-00/?p=105494
  if (FdFlags & (__WASI_FDFLAGS_SYNC | __WASI_FDFLAGS_RSYNC)) {
    // Linux does not implement O_RSYNC and glibc defines O_RSYNC as O_SYNC
    AttributeFlags |=
        winapi::FILE_FLAG_WRITE_THROUGH_ | winapi::FILE_FLAG_NO_BUFFERING_;
    FdFlags &= ~(__WASI_FDFLAGS_SYNC | __WASI_FDFLAGS_RSYNC);
  }
  if (FdFlags & __WASI_FDFLAGS_DSYNC) {
    AttributeFlags |= winapi::FILE_FLAG_WRITE_THROUGH_;
    FdFlags &= ~__WASI_FDFLAGS_DSYNC;
  }
  if (OpenFlags & __WASI_OFLAGS_DIRECTORY) {
    AttributeFlags |=
        winapi::FILE_ATTRIBUTE_DIRECTORY_ | winapi::FILE_FLAG_BACKUP_SEMANTICS_;
    OpenFlags &= ~__WASI_OFLAGS_DIRECTORY;
  }
  if (FdFlags) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  winapi::DWORD_ AccessFlags = 0;
  if (VFSFlags & VFS::Read) {
    AccessFlags |= winapi::FILE_GENERIC_READ_;
    VFSFlags &= ~VFS::Read;
  }
  if (VFSFlags & VFS::Write) {
    AccessFlags |= winapi::FILE_GENERIC_WRITE_;
    VFSFlags &= ~VFS::Write;
  }
  if (VFSFlags) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  if (OpenFlags & ~(__WASI_OFLAGS_CREAT | __WASI_OFLAGS_DIRECTORY |
                    __WASI_OFLAGS_EXCL | __WASI_OFLAGS_TRUNC)) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
  if (OpenFlags & __WASI_OFLAGS_DIRECTORY) {
    return WasiUnexpect(__WASI_ERRNO_NOTDIR);
  }
  winapi::DWORD_ CreationDisposition = 0;
  switch (static_cast<uint16_t>(
      OpenFlags &
      (__WASI_OFLAGS_CREAT | __WASI_OFLAGS_EXCL | __WASI_OFLAGS_TRUNC))) {
  case __WASI_OFLAGS_CREAT | __WASI_OFLAGS_EXCL:
  case __WASI_OFLAGS_CREAT | __WASI_OFLAGS_EXCL | __WASI_OFLAGS_TRUNC:
    CreationDisposition = winapi::CREATE_NEW_;
    break;
  case __WASI_OFLAGS_CREAT | __WASI_OFLAGS_TRUNC:
    CreationDisposition = winapi::CREATE_ALWAYS_;
    break;
  case 0:
  case __WASI_OFLAGS_EXCL:
    CreationDisposition = winapi::OPEN_EXISTING_;
    break;
  case __WASI_OFLAGS_CREAT:
    CreationDisposition = winapi::OPEN_ALWAYS_;
    break;
  case __WASI_OFLAGS_TRUNC:
  case __WASI_OFLAGS_EXCL | __WASI_OFLAGS_TRUNC:
    CreationDisposition = winapi::TRUNCATE_EXISTING_;
    break;
  }

  return std::tuple{AttributeFlags, AccessFlags, CreationDisposition};
}

inline constexpr __wasi_filetype_t
fromFileType(winapi::DWORD_ Attribute, winapi::HANDLE_ Handle) noexcept {
  if (Attribute & winapi::FILE_ATTRIBUTE_DIRECTORY_) {
    return __WASI_FILETYPE_DIRECTORY;
  }
  if (Attribute & winapi::FILE_ATTRIBUTE_SPARSE_FILE_) {
    return __WASI_FILETYPE_REGULAR_FILE;
  }
  if (Attribute & winapi::FILE_ATTRIBUTE_NORMAL_) {
    return __WASI_FILETYPE_REGULAR_FILE;
  }
  if (Attribute & winapi::FILE_ATTRIBUTE_REPARSE_POINT_) {
    return __WASI_FILETYPE_SYMBOLIC_LINK;
  }
  if (winapi::GetFileType(Handle) == winapi::FILE_TYPE_CHAR_) {
    return __WASI_FILETYPE_CHARACTER_DEVICE;
  }
  return __WASI_FILETYPE_UNKNOWN;
}

inline WasiExpect<winapi::DWORD_>
getAttribute(winapi::HANDLE_ Handle) noexcept {
#if NTDDI_VERSION >= NTDDI_VISTA
  winapi::FILE_ATTRIBUTE_TAG_INFO_ FileAttributeInfo;
  if (unlikely(!winapi::GetFileInformationByHandleEx(
          Handle, winapi::FileAttributeTagInfo_, &FileAttributeInfo,
          sizeof(FileAttributeInfo)))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  const auto Attributes = FileAttributeInfo.FileAttributes;
#else
  winapi::BY_HANDLE_FILE_INFORMATION_ FileInfo;
  if (unlikely(!winapi::GetFileInformationByHandle(Handle, &FileInfo))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  const auto Attributes = FileInfo.dwFileAttributes;
#endif

  if (unlikely(Attributes == winapi::INVALID_FILE_ATTRIBUTES_)) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return Attributes;
}

inline WasiExpect<void> forceDirectory(winapi::HANDLE_ Handle) noexcept {
  if (auto Res = getAttribute(Handle); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else if (unlikely(!((*Res) & winapi::FILE_ATTRIBUTE_DIRECTORY_))) {
    return WasiUnexpect(__WASI_ERRNO_NOTDIR);
  }

  return {};
}

inline WasiExpect<std::filesystem::path>
getPath(winapi::HANDLE_ Handle) noexcept {
  // First get the path of the handle
  std::array<wchar_t, winapi::MAX_PATH_> FullPath;
  if (unlikely(!winapi::GetFinalPathNameByHandleW(
          Handle, FullPath.data(), FullPath.size(),
          winapi::FILE_NAME_NORMALIZED_ | winapi::VOLUME_NAME_DOS_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return std::filesystem::path(FullPath.data());
}

inline WasiExpect<std::filesystem::path>
getRelativePath(winapi::HANDLE_ Handle, std::string Path) noexcept {
  // Check if the path is a directory or not
  if (auto Res = forceDirectory(Handle); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  std::filesystem::path FullPath;
  if (auto Res = getPath(Handle); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

  // Append the paths together
  FullPath /= std::filesystem::u8path(Path);
  return FullPath;
}

inline constexpr WasiExpect<int>
toSockOptLevel(__wasi_sock_opt_level_t Level) noexcept {
  switch (Level) {
  case __WASI_SOCK_OPT_LEVEL_SOL_SOCKET:
    return winapi::SOL_SOCKET;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
}

inline constexpr WasiExpect<int>
toSockOptSoName(__wasi_sock_opt_so_t SoName) noexcept {
  switch (SoName) {
  case __WASI_SOCK_OPT_SO_REUSEADDR:
    return winapi::SO_REUSEADDR;
  case __WASI_SOCK_OPT_SO_TYPE:
    return winapi::SO_TYPE;
  case __WASI_SOCK_OPT_SO_ERROR:
    return winapi::SO_ERROR;
  case __WASI_SOCK_OPT_SO_DONTROUTE:
    return winapi::SO_DONTROUTE;
  case __WASI_SOCK_OPT_SO_BROADCAST:
    return winapi::SO_BROADCAST;
  case __WASI_SOCK_OPT_SO_SNDBUF:
    return winapi::SO_SNDBUF;
  case __WASI_SOCK_OPT_SO_RCVBUF:
    return winapi::SO_RCVBUF;
  case __WASI_SOCK_OPT_SO_KEEPALIVE:
    return winapi::SO_KEEPALIVE;
  case __WASI_SOCK_OPT_SO_OOBINLINE:
    return winapi::SO_OOBINLINE;
  case __WASI_SOCK_OPT_SO_LINGER:
    return winapi::SO_LINGER;
  case __WASI_SOCK_OPT_SO_RCVLOWAT:
    return winapi::SO_RCVLOWAT;
  case __WASI_SOCK_OPT_SO_RCVTIMEO:
    return winapi::SO_RCVTIMEO;
  case __WASI_SOCK_OPT_SO_SNDTIMEO:
    return winapi::SO_SNDTIMEO;
  case __WASI_SOCK_OPT_SO_ACCEPTCONN:
    return winapi::SO_ACCEPTCONN;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
}

inline constexpr WasiExpect<int> toAIFlags(__wasi_aiflags_t AIFlags) noexcept {
  int Result = 0;

  if (AIFlags & __WASI_AIFLAGS_AI_PASSIVE) {
    AIFlags &= ~__WASI_AIFLAGS_AI_PASSIVE;
    Result |= winapi::AI_PASSIVE;
  }
  if (AIFlags & __WASI_AIFLAGS_AI_CANONNAME) {
    AIFlags &= ~__WASI_AIFLAGS_AI_CANONNAME;
    Result |= winapi::AI_CANONNAME;
  }
  if (AIFlags & __WASI_AIFLAGS_AI_NUMERICHOST) {
    AIFlags &= ~__WASI_AIFLAGS_AI_NUMERICHOST;
    Result |= winapi::AI_NUMERICHOST;
  }
#if NTDDI_VERSION >= NTDDI_VISTA
  if (AIFlags & __WASI_AIFLAGS_AI_NUMERICSERV) {
    AIFlags &= ~__WASI_AIFLAGS_AI_NUMERICSERV;
    Result |= winapi::AI_NUMERICSERV;
  }
  if (AIFlags & __WASI_AIFLAGS_AI_V4MAPPED) {
    AIFlags &= ~__WASI_AIFLAGS_AI_V4MAPPED;
    Result |= winapi::AI_V4MAPPED;
  }
  if (AIFlags & __WASI_AIFLAGS_AI_ALL) {
    AIFlags &= ~__WASI_AIFLAGS_AI_ALL;
    Result |= winapi::AI_ALL;
  }
  if (AIFlags & __WASI_AIFLAGS_AI_ADDRCONFIG) {
    AIFlags &= ~__WASI_AIFLAGS_AI_ADDRCONFIG;
    Result |= winapi::AI_ADDRCONFIG;
  }
#endif

  if (AIFlags) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
  return Result;
}

inline constexpr WasiExpect<int>
toAddressFamily(__wasi_address_family_t AddressFamily) noexcept {
  switch (AddressFamily) {
  case __WASI_ADDRESS_FAMILY_UNSPEC:
    return winapi::AF_UNSPEC;
  case __WASI_ADDRESS_FAMILY_INET4:
    return winapi::AF_INET;
  case __WASI_ADDRESS_FAMILY_INET6:
    return winapi::AF_INET6;
  default:
    return WasiUnexpect(__WASI_ERRNO_AIFAMILY);
  }
}

inline constexpr WasiExpect<int>
toKnownAddressFamily(__wasi_address_family_t AddressFamily) noexcept {
  switch (AddressFamily) {
  case __WASI_ADDRESS_FAMILY_INET4:
    return winapi::AF_INET;
  case __WASI_ADDRESS_FAMILY_INET6:
    return winapi::AF_INET6;
  default:
    return WasiUnexpect(__WASI_ERRNO_AIFAMILY);
  }
}

inline constexpr WasiExpect<int>
toSockType(__wasi_sock_type_t SockType) noexcept {
  switch (SockType) {
  case __WASI_SOCK_TYPE_SOCK_ANY:
    return 0;
  case __WASI_SOCK_TYPE_SOCK_DGRAM:
    return winapi::SOCK_DGRAM;
  case __WASI_SOCK_TYPE_SOCK_STREAM:
    return winapi::SOCK_STREAM;
  default:
    return WasiUnexpect(__WASI_ERRNO_AISOCKTYPE);
  }
}

inline constexpr WasiExpect<int>
toKnownSockType(__wasi_sock_type_t SockType) noexcept {
  switch (SockType) {
  case __WASI_SOCK_TYPE_SOCK_DGRAM:
    return winapi::SOCK_DGRAM;
  case __WASI_SOCK_TYPE_SOCK_STREAM:
    return winapi::SOCK_STREAM;
  default:
    return WasiUnexpect(__WASI_ERRNO_AISOCKTYPE);
  }
}

inline constexpr WasiExpect<int>
toProtocol(__wasi_protocol_t Protocol) noexcept {
  switch (Protocol) {
  case __WASI_PROTOCOL_IPPROTO_IP:
    return winapi::IPPROTO_IP;
  case __WASI_PROTOCOL_IPPROTO_TCP:
    return winapi::IPPROTO_TCP;
  case __WASI_PROTOCOL_IPPROTO_UDP:
    return winapi::IPPROTO_UDP;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }
}

} // namespace

void HandleHolder::reset() noexcept {
  if (likely(ok())) {
    if (isStdHandle()) {
      // nothing to do
    } else if (likely(!isSocket(&Handle))) {
      winapi::CloseHandle(Handle);
    } else {
      ::closesocket(reinterpret_cast<winapi::SOCKET_>(Handle));
    }
    Handle = nullptr;
  }
}

void FindHolder::reset() noexcept {
  if (likely(ok())) {
    winapi::FindClose(Handle);
    Handle = nullptr;
    Cookie = 0;
  }
}

INode INode::stdIn() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_INPUT_HANDLE_), true);
}

INode INode::stdOut() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_OUTPUT_HANDLE_), true);
}

INode INode::stdErr() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_ERROR_HANDLE_), true);
}

WasiExpect<INode> INode::open(std::string Path, __wasi_oflags_t OpenFlags,
                              __wasi_fdflags_t FdFlags,
                              uint8_t VFSFlags) noexcept {
  winapi::DWORD_ AttributeFlags;
  winapi::DWORD_ AccessFlags;
  winapi::DWORD_ CreationDisposition;
  if (auto Res = getOpenFlags(OpenFlags, FdFlags, VFSFlags); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    std::tie(AttributeFlags, AccessFlags, CreationDisposition) = *Res;
  }

  const winapi::DWORD_ ShareFlags = winapi::FILE_SHARE_READ_ |
                                    winapi::FILE_SHARE_WRITE_ |
                                    winapi::FILE_SHARE_DELETE_;
  const auto FullPath = std::filesystem::u8path(Path);

#if NTDDI_VERSION >= NTDDI_WIN8
  winapi::CREATEFILE2_EXTENDED_PARAMETERS_ Create2ExParams;
  Create2ExParams.dwSize = sizeof(Create2ExParams);
  Create2ExParams.dwFileAttributes = AttributeFlags & 0xFFFF;
  Create2ExParams.dwFileFlags = AttributeFlags & 0xFFF00000;
  Create2ExParams.dwSecurityQosFlags = AttributeFlags & 0x000F0000;
  Create2ExParams.lpSecurityAttributes = nullptr;
  Create2ExParams.hTemplateFile = nullptr;

  HandleHolder FileHandle{winapi::CreateFile2(FullPath.c_str(), AccessFlags,
                                              ShareFlags, CreationDisposition,
                                              &Create2ExParams)};
#else
  HandleHolder FileHandle{
      winapi::CreateFileW(FullPath.c_str(), AccessFlags, ShareFlags, nullptr,
                          CreationDisposition, AttributeFlags, nullptr)};
#endif

  if (unlikely(!FileHandle.ok())) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  INode Result{FileHandle.release()};
  Result.SavedFdFlags = FdFlags;
  return Result;
}

WasiExpect<void> INode::fdAdvise(__wasi_filesize_t, __wasi_filesize_t,
                                 __wasi_advice_t) const noexcept {
  // FIXME: No equivalent function was found for this purpose in the Win32 API
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> INode::fdAllocate(__wasi_filesize_t Offset,
                                   __wasi_filesize_t Len) const noexcept {
  if (unlikely(Offset > std::numeric_limits<int64_t>::max())) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  if (unlikely(Len > std::numeric_limits<int64_t>::max())) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  if (unlikely((Offset + Len) > std::numeric_limits<int64_t>::max())) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  const int64_t RequestSize = static_cast<int64_t>(Offset + Len);

  if (winapi::LARGE_INTEGER_ FileSize;
      unlikely(!winapi::GetFileSizeEx(Handle, &FileSize))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  } else if (FileSize.QuadPart >= RequestSize) {
    // Silence success if current size is larger then requested size.
    return {};
  }

#if NTDDI_VERSION >= NTDDI_VISTA
  winapi::FILE_END_OF_FILE_INFO_ EndOfFileInfo;
  EndOfFileInfo.EndOfFile.QuadPart = RequestSize;

  if (!winapi::SetFileInformationByHandle(Handle, winapi::FileEndOfFileInfo_,
                                          &EndOfFileInfo,
                                          sizeof(EndOfFileInfo))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
#else
  winapi::LARGE_INTEGER_ Old = {.QuadPart = 0};
  if (unlikely(!winapi::SetFilePointerEx(Handle, Old, &Old,
                                         winapi::FILE_CURRENT_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  winapi::LARGE_INTEGER_ New = {.QuadPart = RequestSize};
  if (unlikely(!winapi::SetFilePointerEx(Handle, New, nullptr,
                                         winapi::FILE_BEGIN_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  if (unlikely(!winapi::SetEndOfFile(Handle))) {
    auto LastError = detail::fromLastError(winapi::GetLastError());
    winapi::SetFilePointerEx(Handle, Old, nullptr, winapi::FILE_BEGIN_));
    return WasiUnexpect(LastError);
  }
  winapi::SetFilePointerEx(Handle, Old, nullptr, winapi::FILE_BEGIN_));
#endif

  return {};
}

WasiExpect<void> INode::fdDatasync() const noexcept {
  if (unlikely(!winapi::FlushFileBuffers(Handle))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::fdFdstatGet(__wasi_fdstat_t &FdStat) const noexcept {
  if (auto Res = getAttribute(Handle); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FdStat.fs_filetype = fromFileType(*Res, Handle);
  }
  FdStat.fs_flags = SavedFdFlags;
  return {};
}

WasiExpect<void> INode::fdFdstatSetFlags(__wasi_fdflags_t FdFlags
                                         [[maybe_unused]]) const noexcept {
  // TODO: Reopen Handle?
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void>
INode::fdFilestatGet(__wasi_filestat_t &FileStat) const noexcept {
  winapi::BY_HANDLE_FILE_INFORMATION_ FileInfo;
  if (unlikely(!winapi::GetFileInformationByHandle(Handle, &FileInfo))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  FileStat.dev = FileInfo.dwVolumeSerialNumber;
  FileStat.ino =
      combineHighLow(FileInfo.nFileIndexHigh, FileInfo.nFileIndexLow);
  FileStat.filetype = fromFileType(FileInfo.dwFileAttributes, Handle);
  FileStat.nlink = FileInfo.nNumberOfLinks;
  FileStat.size = combineHighLow(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow);
  FileStat.atim = detail::fromFiletime(FileInfo.ftLastAccessTime);
  FileStat.mtim = detail::fromFiletime(FileInfo.ftLastWriteTime);
  FileStat.ctim = detail::fromFiletime(FileInfo.ftCreationTime);
  return {};
}

WasiExpect<void>
INode::fdFilestatSetSize(__wasi_filesize_t Size) const noexcept {
  if (unlikely(Size > std::numeric_limits<int64_t>::max())) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  const int64_t RequestSize = static_cast<int64_t>(Size);

#if NTDDI_VERSION >= NTDDI_VISTA
  winapi::FILE_END_OF_FILE_INFO_ EndOfFileInfo;
  EndOfFileInfo.EndOfFile.QuadPart = RequestSize;

  if (!winapi::SetFileInformationByHandle(Handle, winapi::FileEndOfFileInfo_,
                                          &EndOfFileInfo,
                                          sizeof(EndOfFileInfo))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
#else
  winapi::LARGE_INTEGER_ Old = {.QuadPart = 0};
  if (unlikely(!winapi::SetFilePointerEx(Handle, Old, &Old,
                                         winapi::FILE_CURRENT_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  winapi::LARGE_INTEGER_ New = {.QuadPart = RequestSize};
  if (unlikely(!winapi::SetFilePointerEx(Handle, New, nullptr,
                                         winapi::FILE_BEGIN_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  if (unlikely(!winapi::SetEndOfFile(Handle))) {
    auto LastError = detail::fromLastError(winapi::GetLastError());
    winapi::SetFilePointerEx(Handle, Old, nullptr, winapi::FILE_BEGIN_));
    return WasiUnexpect(LastError);
  }
  winapi::SetFilePointerEx(Handle, Old, nullptr, winapi::FILE_BEGIN_));
#endif

  return {};
}

WasiExpect<void>
INode::fdFilestatSetTimes(__wasi_timestamp_t ATim, __wasi_timestamp_t MTim,
                          __wasi_fstflags_t FstFlags) const noexcept {
  // Let FileTime be initialized to zero if the times need not be changed
  winapi::FILETIME_ AFileTime = {0, 0};
  winapi::FILETIME_ MFileTime = {0, 0};

  // For setting access time
  if (FstFlags & __WASI_FSTFLAGS_ATIM) {
    AFileTime = detail::toFiletime(ATim);
  } else if (FstFlags & __WASI_FSTFLAGS_ATIM_NOW) {
#if NTDDI_VERSION >= NTDDI_WIN8
    winapi::GetSystemTimePreciseAsFileTime(&AFileTime);
#else
    winapi::GetSystemTimeAsFileTime(&AFileTime);
#endif
  }

  // For setting modification time
  if (FstFlags & __WASI_FSTFLAGS_MTIM) {
    MFileTime = detail::toFiletime(MTim);
  } else if (FstFlags & __WASI_FSTFLAGS_MTIM_NOW) {
#if NTDDI_VERSION >= NTDDI_WIN8
    winapi::GetSystemTimePreciseAsFileTime(&MFileTime);
#else
    winapi::GetSystemTimeAsFileTime(&MFileTime);
#endif
  }

  if (unlikely(!winapi::SetFileTime(Handle, nullptr, &AFileTime, &MFileTime))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::fdPread(Span<Span<uint8_t>> IOVs,
                                __wasi_filesize_t Offset,
                                __wasi_size_t &NRead) const noexcept {
  WasiExpect<void> Result;
  std::vector<winapi::OVERLAPPED_> Queries(IOVs.size());
  winapi::ULARGE_INTEGER_ LocalOffset = {.QuadPart = Offset};

  for (size_t I = 0; I < IOVs.size(); ++I) {
    auto &IOV = IOVs[I];
    auto &Query = Queries[I];
    Query.Offset = LocalOffset.LowPart;
    Query.OffsetHigh = LocalOffset.HighPart;
    Query.Pointer = 0;
    Query.hEvent = nullptr;
    winapi::ReadFileEx(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                       &Query, nullptr);
    if (unlikely(winapi::GetLastError() != winapi::ERROR_IO_PENDING_)) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      Queries.resize(I);
      break;
    }
    LocalOffset.QuadPart += IOV.size();
  }

  NRead = 0;
  for (size_t I = 0; I < Queries.size(); ++I) {
    auto &Query = Queries[I];
    winapi::DWORD_ NumberOfBytesRead = 0;
    if (unlikely(!winapi::GetOverlappedResult(Handle, &Query,
                                              &NumberOfBytesRead, true))) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      winapi::CancelIo(Handle);
      for (size_t J = I + 1; J < Queries.size(); ++J) {
        winapi::GetOverlappedResult(Handle, &Queries[J], nullptr, true);
      }
      break;
    }
    NRead += NumberOfBytesRead;
  }

  return Result;
}

WasiExpect<void> INode::fdPwrite(Span<Span<const uint8_t>> IOVs,
                                 __wasi_filesize_t Offset,
                                 __wasi_size_t &NWritten) const noexcept {
  WasiExpect<void> Result;
  std::vector<winapi::OVERLAPPED_> Queries(IOVs.size());
  winapi::ULARGE_INTEGER_ LocalOffset = {.QuadPart = Offset};

  for (size_t I = 0; I < IOVs.size(); ++I) {
    auto &IOV = IOVs[I];
    auto &Query = Queries[I];
    Query.Offset = LocalOffset.LowPart;
    Query.OffsetHigh = LocalOffset.HighPart;
    Query.Pointer = 0;
    Query.hEvent = nullptr;
    winapi::WriteFileEx(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                        &Query, nullptr);
    if (unlikely(winapi::GetLastError() != winapi::ERROR_IO_PENDING_)) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      Queries.resize(I);
      break;
    }
    LocalOffset.QuadPart += IOV.size();
  }

  NWritten = 0;
  for (size_t I = 0; I < Queries.size(); ++I) {
    auto &Query = Queries[I];
    winapi::DWORD_ NumberOfBytesRead = 0;
    if (unlikely(!winapi::GetOverlappedResult(Handle, &Query,
                                              &NumberOfBytesRead, true))) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      winapi::CancelIo(Handle);
      for (size_t J = I + 1; J < Queries.size(); ++J) {
        winapi::GetOverlappedResult(Handle, &Queries[J], nullptr, true);
      }
      break;
    }
    NWritten += NumberOfBytesRead;
  }

  return Result;
}

WasiExpect<void> INode::fdRead(Span<Span<uint8_t>> IOVs,
                               __wasi_size_t &NRead) const noexcept {
  WasiExpect<void> Result;
  std::vector<winapi::OVERLAPPED_> Queries(IOVs.size());
  winapi::LARGE_INTEGER_ OldOffset = {.QuadPart = 0};
  if (unlikely(!winapi::SetFilePointerEx(Handle, OldOffset, &OldOffset,
                                         winapi::FILE_CURRENT_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  winapi::LARGE_INTEGER_ LocalOffset = OldOffset;

  for (size_t I = 0; I < IOVs.size(); ++I) {
    auto &IOV = IOVs[I];
    auto &Query = Queries[I];
    Query.Offset = LocalOffset.LowPart;
    Query.OffsetHigh = static_cast<winapi::DWORD_>(LocalOffset.HighPart);
    Query.Pointer = 0;
    Query.hEvent = nullptr;
    winapi::ReadFileEx(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                       &Query, nullptr);
    if (unlikely(winapi::GetLastError() != winapi::ERROR_IO_PENDING_)) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      Queries.resize(I);
      break;
    }
    LocalOffset.QuadPart += IOV.size();
  }

  NRead = 0;
  for (size_t I = 0; I < Queries.size(); ++I) {
    auto &Query = Queries[I];
    winapi::DWORD_ NumberOfBytesRead = 0;
    if (unlikely(!winapi::GetOverlappedResult(Handle, &Query,
                                              &NumberOfBytesRead, true))) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      winapi::CancelIo(Handle);
      for (size_t J = I + 1; J < Queries.size(); ++J) {
        winapi::GetOverlappedResult(Handle, &Queries[J], nullptr, true);
      }
      break;
    }
    NRead += NumberOfBytesRead;
  }

  OldOffset.QuadPart += NRead;
  winapi::SetFilePointerEx(Handle, OldOffset, nullptr, winapi::FILE_BEGIN_);

  return Result;
}

WasiExpect<void> INode::fdReaddir(Span<uint8_t> Buffer,
                                  __wasi_dircookie_t Cookie,
                                  __wasi_size_t &Size) noexcept {
  if (unlikely(Cookie < Find.Cookie)) {
    Find.reset();
  }

  winapi::WIN32_FIND_DATAW_ FindData;
  if (unlikely(!Find.ok())) {
    std::filesystem::path FullPath;
    if (auto Res = getRelativePath(Handle, "\\*"); unlikely(!Res)) {
      return WasiUnexpect(Res);
    } else {
      FullPath = std::move(*Res);
    }

    // Begin the search for files
    if (winapi::HANDLE_ FindHandle =
            winapi::FindFirstFileW(FullPath.c_str(), &FindData);
        unlikely(FindHandle == winapi::INVALID_HANDLE_VALUE_)) {
      return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
    } else {
      Find.emplace(FindHandle);
    }
  }

  if (unlikely(Cookie != Find.Cookie)) {
    // seekdir() emulation - go to the Cookie'th file/directory
    while (Find.Cookie < Cookie) {
      if (unlikely(!winapi::FindNextFileW(Find.Handle, &FindData))) {
        return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      }
      ++Find.Cookie;
    }
  }

  bool FindNextResult = true;
  Size = 0;
  do {
    if (!Find.Buffer.empty()) {
      const auto NewDataSize =
          std::min<uint32_t>(static_cast<uint32_t>(Buffer.size()),
                             static_cast<uint32_t>(Find.Buffer.size()));
      std::copy(Find.Buffer.begin(), Find.Buffer.begin() + NewDataSize,
                Buffer.begin());
      Buffer = Buffer.subspan(NewDataSize);
      Size += NewDataSize;
      Find.Buffer.erase(Find.Buffer.begin(), Find.Buffer.begin() + NewDataSize);
      if (unlikely(Buffer.empty())) {
        break;
      }
    }
    std::filesystem::path FilePath = std::filesystem::path(FindData.cFileName);
    std::string UTF8FileName = FilePath.filename().u8string();
    Find.Buffer.resize(sizeof(__wasi_dirent_t) + UTF8FileName.size());
    __wasi_dirent_t *const Dirent =
        reinterpret_cast<__wasi_dirent_t *>(Find.Buffer.data());

    {
#if NTDDI_VERSION >= NTDDI_WIN8
      HandleHolder File{winapi::CreateFile2(
          FilePath.c_str(), winapi::FILE_GENERIC_READ_,
          winapi::FILE_SHARE_READ_, winapi::OPEN_EXISTING_, nullptr)};
#else
      HandleHolder File{
          winapi::CreateFileW(FilePath.c_str(), winapi::FILE_GENERIC_READ_,
                              winapi::FILE_SHARE_READ_, nullptr,
                              winapi::OPEN_EXISTING_, 0, nullptr)};
#endif

      if (unlikely(!File.ok())) {
        return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      }

      winapi::BY_HANDLE_FILE_INFORMATION_ FileInfo;
      if (unlikely(
              !winapi::GetFileInformationByHandle(File.Handle, &FileInfo))) {
        return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      }
      Dirent->d_type = fromFileType(FileInfo.dwFileAttributes, File.Handle);
      Dirent->d_ino =
          combineHighLow(FileInfo.nFileIndexHigh, FileInfo.nFileIndexLow);
    }

    Dirent->d_namlen = static_cast<uint32_t>(UTF8FileName.size());
    Dirent->d_next = ++Find.Cookie;
    std::copy(UTF8FileName.cbegin(), UTF8FileName.cend(),
              Find.Buffer.begin() + sizeof(__wasi_dirent_t));

    // Check if there no more files left or if an error has been encountered
    FindNextResult = winapi::FindNextFileW(Find.Handle, &FindData);
  } while (!Buffer.empty() && FindNextResult);

  if (!FindNextResult) {
    if (winapi::DWORD_ Code = winapi::GetLastError();
        unlikely(Code != winapi::ERROR_NO_MORE_FILES_)) {
      // The FindNextFileW() function has failed
      return WasiUnexpect(detail::fromLastError(Code));
    }
  }

  return {};
}

WasiExpect<void> INode::fdSeek(__wasi_filedelta_t Offset,
                               __wasi_whence_t Whence,
                               __wasi_filesize_t &Size) const noexcept {
  winapi::DWORD_ SysWhence;
  if (auto Res = toWhence(Whence); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysWhence = *Res;
  }

  winapi::LARGE_INTEGER_ Pointer = {.QuadPart = Offset};
  if (unlikely(
          !winapi::SetFilePointerEx(Handle, Pointer, &Pointer, SysWhence))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  Size = static_cast<uint64_t>(Pointer.QuadPart);
  return {};
}

WasiExpect<void> INode::fdSync() const noexcept {
  if (unlikely(!winapi::FlushFileBuffers(Handle))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::fdTell(__wasi_filesize_t &Size) const noexcept {
  winapi::LARGE_INTEGER_ Pointer = {.QuadPart = 0};
  if (unlikely(!winapi::SetFilePointerEx(Handle, Pointer, &Pointer,
                                         winapi::FILE_CURRENT_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  Size = static_cast<uint64_t>(Pointer.QuadPart);
  return {};
}

WasiExpect<void> INode::fdWrite(Span<Span<const uint8_t>> IOVs,
                                __wasi_size_t &NWritten) const noexcept {
  WasiExpect<void> Result;
  std::vector<winapi::OVERLAPPED_> Queries(IOVs.size());
  winapi::LARGE_INTEGER_ OldOffset = {.QuadPart = 0};
  if (unlikely(!winapi::SetFilePointerEx(Handle, OldOffset, &OldOffset,
                                         winapi::FILE_CURRENT_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  winapi::LARGE_INTEGER_ LocalOffset = OldOffset;

  for (size_t I = 0; I < IOVs.size(); ++I) {
    auto &IOV = IOVs[I];
    auto &Query = Queries[I];
    Query.Offset = LocalOffset.LowPart;
    Query.OffsetHigh = static_cast<winapi::DWORD_>(LocalOffset.HighPart);
    Query.Pointer = 0;
    Query.hEvent = nullptr;
    winapi::WriteFileEx(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                        &Query, nullptr);
    if (unlikely(winapi::GetLastError() != winapi::ERROR_IO_PENDING_)) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      Queries.resize(I);
      break;
    }
    LocalOffset.QuadPart += IOV.size();
  }

  NWritten = 0;
  for (size_t I = 0; I < Queries.size(); ++I) {
    auto &Query = Queries[I];
    winapi::DWORD_ NumberOfBytesRead = 0;
    if (unlikely(!winapi::GetOverlappedResult(Handle, &Query,
                                              &NumberOfBytesRead, true))) {
      Result = WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
      winapi::CancelIo(Handle);
      for (size_t J = I + 1; J < Queries.size(); ++J) {
        winapi::GetOverlappedResult(Handle, &Queries[J], nullptr, true);
      }
      break;
    }
    NWritten += NumberOfBytesRead;
  }

  OldOffset.QuadPart += NWritten;
  winapi::SetFilePointerEx(Handle, OldOffset, nullptr, winapi::FILE_BEGIN_);

  return Result;
}

WasiExpect<uint64_t> INode::getNativeHandler() const noexcept {
  return reinterpret_cast<uint64_t>(Handle);
}

WasiExpect<void> INode::pathCreateDirectory(std::string Path) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

  if (unlikely(!winapi::CreateDirectoryW(FullPath.c_str(), nullptr))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void>
INode::pathFilestatGet(std::string Path,
                       __wasi_filestat_t &FileStat) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

#if NTDDI_VERSION >= NTDDI_WIN8
  HandleHolder LocalFileHandle{winapi::CreateFile2(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      winapi::OPEN_EXISTING_, nullptr)};
#else
  HandleHolder LocalFileHandle{winapi::CreateFileW(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      nullptr, winapi::OPEN_EXISTING_, 0, nullptr)};
#endif

  if (unlikely(!LocalFileHandle.ok())) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  winapi::BY_HANDLE_FILE_INFORMATION_ FileInfo;
  if (unlikely(!winapi::GetFileInformationByHandle(LocalFileHandle.Handle,
                                                   &FileInfo))) {
    auto Res = detail::fromLastError(winapi::GetLastError());
    return WasiUnexpect(Res);
  }

  FileStat.dev = FileInfo.dwVolumeSerialNumber;
  FileStat.ino =
      combineHighLow(FileInfo.nFileIndexHigh, FileInfo.nFileIndexLow);
  FileStat.filetype = fromFileType(FileInfo.dwFileAttributes, Handle);
  FileStat.nlink = FileInfo.nNumberOfLinks;
  FileStat.size = combineHighLow(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow);
  FileStat.atim = detail::fromFiletime(FileInfo.ftLastAccessTime);
  FileStat.mtim = detail::fromFiletime(FileInfo.ftLastWriteTime);
  FileStat.ctim = detail::fromFiletime(FileInfo.ftCreationTime);

  return {};
}

WasiExpect<void>
INode::pathFilestatSetTimes(std::string Path, __wasi_timestamp_t ATim,
                            __wasi_timestamp_t MTim,
                            __wasi_fstflags_t FstFlags) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

#if NTDDI_VERSION >= NTDDI_WIN8
  HandleHolder LocalFileHandle{winapi::CreateFile2(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      winapi::OPEN_EXISTING_, nullptr)};
#else
  HandleHolder LocalFileHandle{winapi::CreateFileW(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      nullptr, winapi::OPEN_EXISTING_, 0, nullptr)};
#endif

  if (unlikely(!LocalFileHandle.ok())) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  // Let FileTime be initialized to zero if the times need not be changed
  winapi::FILETIME_ AFileTime = {0, 0};
  winapi::FILETIME_ MFileTime = {0, 0};

  // For setting access time
  if (FstFlags & __WASI_FSTFLAGS_ATIM) {
    AFileTime = detail::toFiletime(ATim);
  } else if (FstFlags & __WASI_FSTFLAGS_ATIM_NOW) {
#if NTDDI_VERSION >= NTDDI_WIN8
    winapi::GetSystemTimePreciseAsFileTime(&AFileTime);
#else
    winapi::GetSystemTimeAsFileTime(&AFileTime);
#endif
  }

  // For setting modification time
  if (FstFlags & __WASI_FSTFLAGS_MTIM) {
    MFileTime = detail::toFiletime(MTim);
  } else if (FstFlags & __WASI_FSTFLAGS_MTIM_NOW) {
#if NTDDI_VERSION >= NTDDI_WIN8
    winapi::GetSystemTimePreciseAsFileTime(&MFileTime);
#else
    winapi::GetSystemTimeAsFileTime(&MFileTime);
#endif
  }

  if (unlikely(!winapi::SetFileTime(LocalFileHandle.Handle, nullptr, &AFileTime,
                                    &MFileTime))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::pathLink(const INode &Old, std::string OldPath,
                                 const INode &New,
                                 std::string NewPath) noexcept {
  std::filesystem::path OldFullPath;
  if (auto Res = getRelativePath(Old.Handle, OldPath); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    OldFullPath = std::move(*Res);
  }
  std::filesystem::path NewFullPath;
  if (auto Res = getRelativePath(New.Handle, NewPath); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    NewFullPath = std::move(*Res);
  }

  // Create the hard link from the paths
  if (unlikely(!winapi::CreateHardLinkW(NewFullPath.c_str(),
                                        OldFullPath.c_str(), nullptr))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<INode> INode::pathOpen(std::string Path, __wasi_oflags_t OpenFlags,
                                  __wasi_fdflags_t FdFlags,
                                  uint8_t VFSFlags) const noexcept {
  winapi::DWORD_ AttributeFlags;
  winapi::DWORD_ AccessFlags;
  winapi::DWORD_ CreationDisposition;
  if (auto Res = getOpenFlags(OpenFlags, FdFlags, VFSFlags); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    std::tie(AttributeFlags, AccessFlags, CreationDisposition) = *Res;
  }

  const winapi::DWORD_ ShareFlags = winapi::FILE_SHARE_READ_ |
                                    winapi::FILE_SHARE_WRITE_ |
                                    winapi::FILE_SHARE_DELETE_;

  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

#if NTDDI_VERSION >= NTDDI_WIN8
  winapi::CREATEFILE2_EXTENDED_PARAMETERS_ Create2ExParams;
  Create2ExParams.dwSize = sizeof(Create2ExParams);
  Create2ExParams.dwFileAttributes = AttributeFlags & 0xFFFF;
  Create2ExParams.dwFileFlags = AttributeFlags & 0xFFF00000;
  Create2ExParams.dwSecurityQosFlags = AttributeFlags & 0x000F0000;
  Create2ExParams.lpSecurityAttributes = nullptr;
  Create2ExParams.hTemplateFile = nullptr;

  HandleHolder FileHandle{winapi::CreateFile2(FullPath.c_str(), AccessFlags,
                                              ShareFlags, CreationDisposition,
                                              &Create2ExParams)};
#else
  HandleHolder FileHandle{
      winapi::CreateFileW(FullPath.c_str(), AccessFlags, ShareFlags, nullptr,
                          CreationDisposition, AttributeFlags, nullptr)};
#endif

  if (unlikely(!FileHandle.ok())) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  INode Result{FileHandle.release()};
  Result.SavedFdFlags = FdFlags;
  return Result;
}

WasiExpect<void> INode::pathReadlink(std::string Path, Span<char> Buffer,
                                     __wasi_size_t &NRead) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

  // Fill the Buffer with the contents of the link
#if NTDDI_VERSION >= NTDDI_WIN8
  winapi::CREATEFILE2_EXTENDED_PARAMETERS_ Create2ExParams;
  Create2ExParams.dwSize = sizeof(Create2ExParams);
  Create2ExParams.dwFileAttributes = 0;
  Create2ExParams.dwFileFlags = winapi::FILE_FLAG_OPEN_REPARSE_POINT_;
  Create2ExParams.dwSecurityQosFlags = 0;
  Create2ExParams.lpSecurityAttributes = nullptr;
  Create2ExParams.hTemplateFile = nullptr;

  HandleHolder LocalFileHandle{winapi::CreateFile2(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      winapi::OPEN_EXISTING_, &Create2ExParams)};
#else
  HandleHolder LocalFileHandle{winapi::CreateFileW(
      FullPath.c_str(), winapi::FILE_GENERIC_READ_, winapi::FILE_SHARE_READ_,
      nullptr, winapi::OPEN_EXISTING_, winapi::FILE_FLAG_OPEN_REPARSE_POINT_,
      nullptr)};
#endif

  if (unlikely(!LocalFileHandle.ok())) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  std::array<wchar_t, winapi::MAX_PATH_> LocalBuffer;
  if (winapi::DWORD_ Size = winapi::GetFinalPathNameByHandleW(
          LocalFileHandle.Handle, LocalBuffer.data(),
          static_cast<uint32_t>(LocalBuffer.size()),
          winapi::FILE_NAME_NORMALIZED_);
      unlikely(Size == 0)) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  } else {
    const auto U8Data =
        std::filesystem::path(std::wstring_view(LocalBuffer.data(), Size))
            .u8string();
    NRead = static_cast<uint32_t>(std::min(Buffer.size(), U8Data.size()));
    std::copy_n(U8Data.begin(), NRead, Buffer.begin());
  }
  return {};
}

WasiExpect<void> INode::pathRemoveDirectory(std::string Path) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

  if (unlikely(!winapi::RemoveDirectoryW(FullPath.c_str()))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::pathRename(const INode &Old, std::string OldPath,
                                   const INode &New,
                                   std::string NewPath) noexcept {
  std::filesystem::path OldFullPath;
  if (auto Res = getRelativePath(Old.Handle, OldPath); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    OldFullPath = std::move(*Res);
  }
  std::filesystem::path NewFullPath;
  if (auto Res = getRelativePath(New.Handle, NewPath); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    NewFullPath = std::move(*Res);
  }

  // Rename the file from the paths
  if (unlikely(!winapi::MoveFileExW(OldFullPath.c_str(), NewFullPath.c_str(),
                                    winapi::MOVEFILE_REPLACE_EXISTING_))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<void> INode::pathSymlink(std::string OldPath,
                                    std::string NewPath) const noexcept {
#if NTDDI_VERSION >= NTDDI_VISTA
  std::filesystem::path NewFullPath;
  if (auto Res = getRelativePath(Handle, NewPath); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    NewFullPath = std::move(*Res);
  }
  const std::filesystem::path OldU8Path = std::filesystem::u8path(OldPath);

  winapi::DWORD_ TargetType = 0;
  if (OldU8Path.filename().empty()) {
    TargetType = winapi::SYMBOLIC_LINK_FLAG_DIRECTORY_;
  }

  if (unlikely(!winapi::CreateSymbolicLinkW(NewFullPath.c_str(),
                                            OldU8Path.c_str(), TargetType))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  return {};
#else
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
#endif
}

WasiExpect<void> INode::pathUnlinkFile(std::string Path) const noexcept {
  std::filesystem::path FullPath;
  if (auto Res = getRelativePath(Handle, Path); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    FullPath = std::move(*Res);
  }

  if (unlikely(!winapi::DeleteFileW(FullPath.c_str()))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<Poller> INode::pollOneoff(__wasi_size_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<Epoller> INode::epollOneoff(__wasi_size_t, int) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> INode::getAddrinfo(std::string_view Node,
                                    std::string_view Service,
                                    const __wasi_addrinfo_t &Hint,
                                    uint32_t MaxResLength,
                                    Span<__wasi_addrinfo_t *> WasiAddrinfoArray,
                                    Span<__wasi_sockaddr_t *> WasiSockaddrArray,
                                    Span<char *> AiAddrSaDataArray,
                                    Span<char *> AiCanonnameArray,
                                    /*Out*/ __wasi_size_t &ResLength) noexcept {
  struct winapi::addrinfo SysHint;
  if (auto Res = toAIFlags(Hint.ai_flags); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysHint.ai_flags = *Res;
  }
  if (auto Res = toAddressFamily(Hint.ai_family); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysHint.ai_family = *Res;
  }
  if (auto Res = toSockType(Hint.ai_socktype); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysHint.ai_socktype = *Res;
  }
  if (auto Res = toProtocol(Hint.ai_protocol); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysHint.ai_protocol = *Res;
  }
  SysHint.ai_addrlen = Hint.ai_addrlen;
  SysHint.ai_addr = nullptr;
  SysHint.ai_canonname = nullptr;
  SysHint.ai_next = nullptr;

  const auto [NodeCStr, NodeBuf] = createNullTerminatedString(Node);
  const auto [ServiceCStr, ServiceBuf] = createNullTerminatedString(Service);

  struct winapi::addrinfo *SysResPtr = nullptr;
  if (auto Res = ::getaddrinfo(NodeCStr, ServiceCStr, &SysHint, &SysResPtr);
      unlikely(Res != 0)) {
    // By MSDN, on failure, getaddrinfo returns a nonzero Windows Sockets error
    // code.
    return WasiUnexpect(fromWSAError(Res));
  }
  // calculate ResLength
  if (ResLength = calculateAddrinfoLinkedListSize(SysResPtr);
      ResLength > MaxResLength) {
    ResLength = MaxResLength;
  }

  struct winapi::addrinfo *SysResItem = SysResPtr;
  for (uint32_t Idx = 0; Idx < ResLength; Idx++) {
    auto &CurAddrinfo = WasiAddrinfoArray[Idx];
    CurAddrinfo->ai_flags = fromAIFlags(SysResItem->ai_flags);
    CurAddrinfo->ai_socktype = fromSockType(SysResItem->ai_socktype);
    CurAddrinfo->ai_protocol = fromProtocol(SysResItem->ai_protocol);
    CurAddrinfo->ai_family = fromAddressFamily(SysResItem->ai_family);
    CurAddrinfo->ai_addrlen = static_cast<uint32_t>(SysResItem->ai_addrlen);

    // process ai_canonname in addrinfo
    if (SysResItem->ai_canonname != nullptr) {
      CurAddrinfo->ai_canonname_len =
          static_cast<uint32_t>(std::strlen(SysResItem->ai_canonname));
      auto &CurAiCanonname = AiCanonnameArray[Idx];
      std::memcpy(CurAiCanonname, SysResItem->ai_canonname,
                  CurAddrinfo->ai_canonname_len + 1);
    } else {
      CurAddrinfo->ai_canonname_len = 0;
    }

    // process socket address
    if (SysResItem->ai_addrlen > 0) {
      auto &CurSockaddr = WasiSockaddrArray[Idx];

      // process sa_data in socket address
      size_t SaSize = 0;
      switch (CurSockaddr->sa_family) {
      case __WASI_ADDRESS_FAMILY_INET4:
        SaSize = sizeof(struct winapi::sockaddr_in) -
                 sizeof(winapi::sockaddr_in::sin_family);
        break;
      case __WASI_ADDRESS_FAMILY_INET6:
        SaSize = sizeof(struct winapi::sockaddr_in6) -
                 sizeof(winapi::sockaddr_in6::sin6_family);
        break;
      default:
        continue;
      }
      std::memcpy(AiAddrSaDataArray[Idx], SysResItem->ai_addr->sa_data, SaSize);
      CurSockaddr->sa_data_len = static_cast<__wasi_size_t>(SaSize);
      CurSockaddr->sa_family =
          fromAddressFamily(SysResItem->ai_addr->sa_family);
    }
    // process ai_next in addrinfo
    SysResItem = SysResItem->ai_next;
  }
  winapi::freeaddrinfo(SysResPtr);

  return {};
}

WasiExpect<INode> INode::sockOpen(__wasi_address_family_t AddressFamily,
                                  __wasi_sock_type_t SockType) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysAddressFamily;
  if (auto Res = toKnownAddressFamily(AddressFamily); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysAddressFamily = *Res;
  }

  int SysType;
  if (auto Res = toKnownSockType(SockType); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysType = *Res;
  }

  const int SysProtocol = winapi::IPPROTO_IP;

  if (auto NewSock = winapi::socket(SysAddressFamily, SysType, SysProtocol);
      unlikely(NewSock == winapi::INVALID_SOCKET_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    INode New(toHandle(NewSock));
    return New;
  }
}

WasiExpect<void> INode::sockBindV1(uint8_t *Address, uint8_t AddressLength,
                                   uint16_t Port) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  if (AddressLength == 4) {
    struct winapi::sockaddr_in ServerAddr;
    ServerAddr.sin_family = winapi::AF_INET;
    ServerAddr.sin_port = winapi::htons(Port);
    std::memcpy(&ServerAddr.sin_addr.s_addr, Address, AddressLength);
    if (auto Res = winapi::bind(
            toSocket(Handle),
            reinterpret_cast<struct winapi::sockaddr *>(&ServerAddr),
            sizeof(ServerAddr));
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
  } else if (AddressLength == 16) {
    struct winapi::sockaddr_in6 ServerAddr;
    std::memset(&ServerAddr, 0, sizeof(ServerAddr));
    ServerAddr.sin6_family = winapi::AF_INET6;
    ServerAddr.sin6_port = winapi::htons(Port);
    std::memcpy(ServerAddr.sin6_addr.s6_addr, Address, AddressLength);
    if (auto Res = winapi::bind(
            toSocket(Handle),
            reinterpret_cast<struct winapi::sockaddr *>(&ServerAddr),
            sizeof(ServerAddr));
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
  }
  return {};
}

WasiExpect<void> INode::sockBindV2(uint8_t *AddressBuf, uint8_t AddressLength,
                                   uint16_t Port) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysAddressFamily;
  uint8_t *Address;
  if (auto Res = resolveAddressFamilyAndAddress(AddressBuf, AddressLength);
      unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    std::tie(SysAddressFamily, Address) = *Res;
  }

  struct winapi::sockaddr_in ServerAddr4 = {};
  struct winapi::sockaddr_in6 ServerAddr6 = {};
  struct winapi::sockaddr *ServerAddr = nullptr;
  winapi::socklen_t RealSize = 0;

  if (SysAddressFamily == winapi::AF_INET) {
    ServerAddr = reinterpret_cast<struct winapi::sockaddr *>(&ServerAddr4);
    RealSize = sizeof(ServerAddr4);

    ServerAddr4.sin_family = winapi::AF_INET;
    ServerAddr4.sin_port = winapi::htons(Port);
    std::memcpy(&ServerAddr4.sin_addr, Address, sizeof(struct winapi::in_addr));
  } else if (SysAddressFamily == winapi::AF_INET6) {
    ServerAddr = reinterpret_cast<struct winapi::sockaddr *>(&ServerAddr6);
    RealSize = sizeof(ServerAddr6);

    ServerAddr6.sin6_family = winapi::AF_INET6;
    ServerAddr6.sin6_port = winapi::htons(Port);
    ServerAddr6.sin6_flowinfo = 0;
    std::memcpy(&ServerAddr6.sin6_addr.s6_addr, Address,
                sizeof(struct winapi::in6_addr));
  } else {
    assumingUnreachable();
  }

  if (auto Res = winapi::bind(toSocket(Handle), ServerAddr, RealSize);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }
  return {};
}

WasiExpect<void> INode::sockListen(int32_t Backlog) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  if (auto Res = winapi::listen(toSocket(Handle), Backlog);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }
  return {};
}

WasiExpect<INode> INode::sockAcceptV1() noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  struct winapi::sockaddr_in ServerSocketAddr;
  ServerSocketAddr.sin_family = winapi::AF_INET;
  ServerSocketAddr.sin_addr.s_addr = winapi::INADDR_ANY;
  winapi::socklen_t AddressLen = sizeof(ServerSocketAddr);

  if (auto NewSock = winapi::accept(
          toSocket(Handle),
          reinterpret_cast<struct winapi::sockaddr *>(&ServerSocketAddr),
          &AddressLen);
      unlikely(NewSock == winapi::INVALID_SOCKET_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    INode New(toHandle(NewSock));
    return New;
  }
}

WasiExpect<INode> INode::sockAcceptV2(__wasi_fdflags_t FdFlags) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  winapi::SOCKET_ NewSock;
  if (NewSock = winapi::accept(toSocket(Handle), nullptr, nullptr);
      unlikely(NewSock == winapi::INVALID_SOCKET_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  INode New(toHandle(NewSock));
  winapi::u_long SysNonBlockFlag = 0;
  if (FdFlags) {
    if (FdFlags & __WASI_FDFLAGS_NONBLOCK) {
      SysNonBlockFlag = 1;
    }
  }

  long Cmd = static_cast<long>(winapi::FIONBIO);
  if (auto Res = winapi::ioctlsocket(NewSock, Cmd, &SysNonBlockFlag);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    return New;
  }
}

WasiExpect<void> INode::sockConnectV1(uint8_t *Address, uint8_t AddressLength,
                                      uint16_t Port) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  if (AddressLength == 4) {
    struct winapi::sockaddr_in ClientSocketAddr;
    ClientSocketAddr.sin_family = winapi::AF_INET;
    ClientSocketAddr.sin_port = winapi::htons(Port);
    std::memcpy(&ClientSocketAddr.sin_addr.s_addr, Address, AddressLength);

    if (auto Res = winapi::connect(
            toSocket(Handle),
            reinterpret_cast<struct winapi::sockaddr *>(&ClientSocketAddr),
            sizeof(ClientSocketAddr));
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
  } else if (AddressLength == 16) {
    struct winapi::sockaddr_in6 ClientSocketAddr;

    ClientSocketAddr.sin6_family = winapi::AF_INET6;
    ClientSocketAddr.sin6_port = winapi::htons(Port);
    std::memcpy(ClientSocketAddr.sin6_addr.s6_addr, Address, AddressLength);
    if (auto Res = winapi::connect(
            toSocket(Handle),
            reinterpret_cast<struct winapi::sockaddr *>(&ClientSocketAddr),
            sizeof(ClientSocketAddr));
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
  }
  return {};
}

WasiExpect<void> INode::sockConnectV2(uint8_t *AddressBuf,
                                      uint8_t AddressLength,
                                      uint16_t Port) noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysAddressFamily;
  uint8_t *Address;
  if (auto Res = resolveAddressFamilyAndAddress(AddressBuf, AddressLength);
      unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    std::tie(SysAddressFamily, Address) = *Res;
  }

  struct winapi::sockaddr_in ClientAddr4 {};
  struct winapi::sockaddr_in6 ClientAddr6 {};
  struct winapi::sockaddr *ClientAddr = nullptr;
  int RealSize = 0;

  if (SysAddressFamily == winapi::AF_INET) {
    ClientAddr = reinterpret_cast<struct winapi::sockaddr *>(&ClientAddr4);
    RealSize = sizeof(ClientAddr4);

    ClientAddr4.sin_family = winapi::AF_INET;
    ClientAddr4.sin_port = winapi::htons(Port);
    std::memcpy(&ClientAddr4.sin_addr, Address, sizeof(struct winapi::in_addr));
  } else if (SysAddressFamily == winapi::AF_INET6) {
    ClientAddr = reinterpret_cast<struct winapi::sockaddr *>(&ClientAddr6);
    RealSize = sizeof(ClientAddr6);

    ClientAddr6.sin6_family = winapi::AF_INET6;
    ClientAddr6.sin6_flowinfo = 0;
    ClientAddr6.sin6_port = winapi::htons(Port);
    std::memcpy(&ClientAddr6.sin6_addr, Address,
                sizeof(struct winapi::in6_addr));
  } else {
    assumingUnreachable();
  }

  if (auto Res = winapi::connect(toSocket(Handle), ClientAddr, RealSize);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }
  return {};
}

WasiExpect<void> INode::sockRecv(Span<Span<uint8_t>> RiData,
                                 __wasi_riflags_t RiFlags, __wasi_size_t &NRead,
                                 __wasi_roflags_t &RoFlags) const noexcept {
  return sockRecvFromV1(RiData, RiFlags, nullptr, 0, NRead, RoFlags);
}

WasiExpect<void>
INode::sockRecvFromV1(Span<Span<uint8_t>> RiData, __wasi_riflags_t RiFlags,
                      uint8_t *Address, uint8_t AddressLength,
                      __wasi_size_t &NRead,
                      __wasi_roflags_t &RoFlags) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  if (AddressLength != 4 && AddressLength != 16) {
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  // recvmsg is not available on WINDOWS. fall back to call recvfrom

  int SysRiFlags = 0;
  if (RiFlags & __WASI_RIFLAGS_RECV_PEEK) {
    SysRiFlags |= winapi::MSG_PEEK;
  }
#if NTDDI_VERSION >= NTDDI_WS03
  if (RiFlags & __WASI_RIFLAGS_RECV_WAITALL) {
    SysRiFlags |= winapi::MSG_WAITALL;
  }
#endif

  std::size_t TmpBufSize = 0;
  for (auto &IOV : RiData) {
    TmpBufSize += IOV.size();
  }

  std::vector<uint8_t> TmpBuf(TmpBufSize, 0);

  struct winapi::sockaddr_storage SockAddrStorage;

  int MaxAllowLength = 0;
  if (AddressLength == 4) {
    MaxAllowLength = sizeof(struct winapi::sockaddr_in);
  } else if (AddressLength == 16) {
    MaxAllowLength = sizeof(struct winapi::sockaddr_in6);
  } else {
    assumingUnreachable();
  }

  if (auto Res = winapi::recvfrom(
          toSocket(Handle), reinterpret_cast<char *>(TmpBuf.data()),
          static_cast<int>(TmpBufSize), SysRiFlags,
          reinterpret_cast<struct winapi::sockaddr *>(&SockAddrStorage),
          &MaxAllowLength);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    NRead = static_cast<__wasi_size_t>(Res);
  }

  if (AddressLength == 4) {
    std::memcpy(
        Address,
        &reinterpret_cast<struct winapi::sockaddr_in *>(&SockAddrStorage)
             ->sin_addr,
        AddressLength);
  } else if (AddressLength == 16) {
    std::memcpy(
        Address,
        &reinterpret_cast<struct winapi::sockaddr_in6 *>(&SockAddrStorage)
             ->sin6_addr,
        AddressLength);
  } else {
    assumingUnreachable();
  }

  RoFlags = static_cast<__wasi_roflags_t>(0);
  // TODO : check MSG_TRUNC

  size_t BeginIdx = 0;
  for (auto &IOV : RiData) {
    std::copy(TmpBuf.data() + BeginIdx, TmpBuf.data() + BeginIdx + IOV.size(),
              IOV.begin());
    BeginIdx += IOV.size();
  }

  return {};
}

WasiExpect<void>
INode::sockRecvFromV2(Span<Span<uint8_t>> RiData, __wasi_riflags_t RiFlags,
                      uint8_t *AddressBuf, uint8_t AddressLength,
                      uint32_t *PortPtr, __wasi_size_t &NRead,
                      __wasi_roflags_t &RoFlags) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  // recvmsg is not available on WINDOWS. fall back to call recvfrom

  uint8_t *Address = nullptr;
  __wasi_address_family_t *SysAddressFamily = nullptr;
  __wasi_address_family_t Dummy; // Write garbage on fallback mode.

  if (AddressBuf) {
    if (AddressLength != sizeof(UniversalAddress)) {
      // Fallback
      SysAddressFamily = &Dummy;
      Address = AddressBuf;
    } else {
      auto *UA = reinterpret_cast<UniversalAddress *>(AddressBuf);
      SysAddressFamily = &UA->AddressFamily;
      Address = UA->Address;
      AddressLength = static_cast<uint8_t>(std::size(UA->Address));
    }
  }

  int SysRiFlags = 0;
  if (RiFlags & __WASI_RIFLAGS_RECV_PEEK) {
    SysRiFlags |= winapi::MSG_PEEK;
  }
#if NTDDI_VERSION >= NTDDI_WS03
  if (RiFlags & __WASI_RIFLAGS_RECV_WAITALL) {
    SysRiFlags |= winapi::MSG_WAITALL;
  }
#endif

  size_t TotalBufSize = std::transform_reduce(
      RiData.begin(), RiData.end(), static_cast<size_t>(0), std::plus<>(),
      [](auto &IOV) noexcept { return IOV.size(); });
  std::vector<uint8_t> TotalBuf(TotalBufSize);

  struct winapi::sockaddr_storage SockAddrStorage;
  int MaxAllowLength = sizeof(SockAddrStorage);

  if (auto Res = winapi::recvfrom(
          toSocket(Handle), reinterpret_cast<char *>(TotalBuf.data()),
          static_cast<int>(TotalBuf.size()), SysRiFlags,
          reinterpret_cast<struct winapi::sockaddr *>(&SockAddrStorage),
          &MaxAllowLength);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    NRead = static_cast<__wasi_size_t>(Res);
  }

  if (AddressBuf) {
    *SysAddressFamily = fromAddressFamily(SockAddrStorage.ss_family);
    if (SockAddrStorage.ss_family == winapi::AF_INET) {
      std::memcpy(
          Address,
          &reinterpret_cast<struct winapi::sockaddr_in *>(&SockAddrStorage)
               ->sin_addr,
          std::min<size_t>(sizeof(struct winapi::in_addr), AddressLength));
    } else if (SockAddrStorage.ss_family == winapi::AF_INET6) {
      std::memcpy(
          Address,
          &reinterpret_cast<struct winapi::sockaddr_in6 *>(&SockAddrStorage)
               ->sin6_addr,
          std::min<size_t>(sizeof(struct winapi::in6_addr), AddressLength));
    } else {
      assumingUnreachable();
    }
  }

  if (PortPtr) {
    *SysAddressFamily = fromAddressFamily(SockAddrStorage.ss_family);
    if (SockAddrStorage.ss_family == winapi::AF_INET) {
      *PortPtr =
          reinterpret_cast<struct winapi::sockaddr_in *>(&SockAddrStorage)
              ->sin_port;
    } else if (SockAddrStorage.ss_family == winapi::AF_INET6) {
      *PortPtr =
          reinterpret_cast<struct winapi::sockaddr_in6 *>(&SockAddrStorage)
              ->sin6_port;
    } else {
      assumingUnreachable();
    }
  }

  RoFlags = static_cast<__wasi_roflags_t>(0);
  // TODO : check MSG_TRUNC

  Span<uint8_t> TotalBufView(TotalBuf);
  for (auto &IOV : RiData) {
    const auto Size = std::min(IOV.size(), TotalBufView.size());
    std::copy_n(TotalBufView.begin(), Size, IOV.begin());
    TotalBufView = TotalBufView.subspan(Size);
    if (TotalBufView.empty()) {
      break;
    }
  }

  return {};
}

WasiExpect<void> INode::sockSend(Span<Span<const uint8_t>> SiData,
                                 __wasi_siflags_t SiFlags,
                                 __wasi_size_t &NWritten) const noexcept {
  return sockSendTo(SiData, SiFlags, nullptr, 0, 0, NWritten);
}

WasiExpect<void> INode::sockSendTo(Span<Span<const uint8_t>> SiData,
                                   __wasi_siflags_t, uint8_t *AddressBuf,
                                   uint8_t AddressLength, int32_t Port,
                                   __wasi_size_t &NWritten) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  // sendmsg is not available on WINDOWS. fall back to call sendto
  int SysSiFlags = 0;

  uint8_t *Address = nullptr;
  int SysAddressFamily = 0;
  if (auto Res = resolveAddressFamilyAndAddress(AddressBuf, AddressLength);
      unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    std::tie(SysAddressFamily, Address) = *Res;
  }

  size_t TotalBufSize = std::transform_reduce(
      SiData.begin(), SiData.end(), static_cast<size_t>(0), std::plus<>(),
      [](auto &IOV) noexcept { return IOV.size(); });
  std::vector<uint8_t> TotalBuf(TotalBufSize);
  Span<uint8_t> TotalBufView(TotalBuf);
  for (auto &IOV : SiData) {
    std::copy_n(IOV.begin(), IOV.size(), TotalBufView.begin());
    TotalBufView = TotalBufView.subspan(IOV.size());
  }
  assuming(TotalBufView.empty());

  struct winapi::sockaddr_in ClientAddr4 = {};
  struct winapi::sockaddr_in6 ClientAddr6 = {};
  struct winapi::sockaddr *ClientAddr = nullptr;
  winapi::socklen_t RealSize = 0;

  if (Address) {
    if (SysAddressFamily == winapi::AF_INET) {
      ClientAddr = reinterpret_cast<struct winapi::sockaddr *>(&ClientAddr4);
      RealSize = sizeof(ClientAddr4);

      ClientAddr4.sin_family = winapi::AF_INET;
      ClientAddr4.sin_port = winapi::htons(static_cast<winapi::u_short>(Port));
      std::memcpy(&ClientAddr4.sin_addr, Address,
                  sizeof(struct winapi::in_addr));
    } else if (SysAddressFamily == winapi::AF_INET6) {
      ClientAddr = reinterpret_cast<struct winapi::sockaddr *>(&ClientAddr6);
      RealSize = sizeof(ClientAddr6);

      ClientAddr6.sin6_family = winapi::AF_INET6;
      ClientAddr6.sin6_flowinfo = 0;
      ClientAddr6.sin6_port = winapi::htons(static_cast<winapi::u_short>(Port));
      std::memcpy(&ClientAddr6.sin6_addr, Address,
                  sizeof(struct winapi::in6_addr));
    }
  }

  if (auto Res = winapi::sendto(
          toSocket(Handle), reinterpret_cast<char *>(TotalBuf.data()),
          static_cast<int>(TotalBuf.size()), SysSiFlags, ClientAddr, RealSize);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  } else {
    NWritten = static_cast<__wasi_size_t>(Res);
  }

  return {};
}

WasiExpect<void> INode::sockShutdown(__wasi_sdflags_t SdFlags) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysFlags;
  switch (static_cast<uint8_t>(SdFlags)) {
  case __WASI_SDFLAGS_RD:
    SysFlags = winapi::SD_RECEIVE;
    break;
  case __WASI_SDFLAGS_WR:
    SysFlags = winapi::SD_SEND;
    break;
  case __WASI_SDFLAGS_RD | __WASI_SDFLAGS_WR:
    SysFlags = winapi::SD_BOTH;
    break;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  if (auto Res = winapi::shutdown(toSocket(Handle), SysFlags);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  return {};
}

WasiExpect<void> INode::sockGetOpt(__wasi_sock_opt_level_t SockOptLevel,
                                   __wasi_sock_opt_so_t SockOptName,
                                   void *FlagPtr,
                                   uint32_t *FlagSizePtr) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysSockOptLevel;
  if (auto Res = toSockOptLevel(SockOptLevel); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysSockOptLevel = *Res;
  }
  int SysSockOptName;
  if (auto Res = toSockOptSoName(SockOptName); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysSockOptName = *Res;
  }
  auto UnsafeFlagSizePtr = reinterpret_cast<winapi::socklen_t *>(FlagSizePtr);
  if (SockOptName == __WASI_SOCK_OPT_SO_ERROR) {
    char ErrorCode = 0;
    int *WasiErrorPtr = static_cast<int *>(FlagPtr);
    if (auto Res =
            winapi::getsockopt(toSocket(Handle), SysSockOptLevel,
                               SysSockOptName, &ErrorCode, UnsafeFlagSizePtr);
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
    *WasiErrorPtr = fromErrNo(ErrorCode);
  } else {
    char *CFlagPtr = static_cast<char *>(FlagPtr);
    if (auto Res =
            winapi::getsockopt(toSocket(Handle), SysSockOptLevel,
                               SysSockOptName, CFlagPtr, UnsafeFlagSizePtr);
        unlikely(Res == winapi::SOCKET_ERROR_)) {
      return WasiUnexpect(detail::fromWSALastError());
    }
  }

  return {};
}

WasiExpect<void> INode::sockSetOpt(__wasi_sock_opt_level_t SockOptLevel,
                                   __wasi_sock_opt_so_t SockOptName,
                                   void *FlagPtr,
                                   uint32_t FlagSize) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  int SysSockOptLevel;
  if (auto Res = toSockOptLevel(SockOptLevel); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysSockOptLevel = *Res;
  }
  int SysSockOptName;
  if (auto Res = toSockOptSoName(SockOptName); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    SysSockOptName = *Res;
  }
  char *CFlagPtr = static_cast<char *>(FlagPtr);
  auto UnsafeFlagSize = static_cast<winapi::socklen_t>(FlagSize);

  if (auto Res = winapi::setsockopt(toSocket(Handle), SysSockOptLevel,
                                    SysSockOptName, CFlagPtr, UnsafeFlagSize);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  return {};
}

WasiExpect<void> INode::sockGetLocalAddrV1(uint8_t *AddressPtr,
                                           uint32_t *AddrTypePtr,
                                           uint32_t *PortPtr) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  struct winapi::sockaddr_storage SocketAddr;
  winapi::socklen_t Slen = sizeof(SocketAddr);
  std::memset(&SocketAddr, 0, sizeof(SocketAddr));

  if (auto Res = winapi::getsockname(
          toSocket(Handle),
          reinterpret_cast<struct winapi::sockaddr *>(&SocketAddr), &Slen);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  size_t AddrLen = 4;
  if (Slen != 16) {
    AddrLen = 16;
  }

  if (SocketAddr.ss_family == winapi::AF_INET) {
    *AddrTypePtr = 4;
    auto SocketAddrv4 =
        reinterpret_cast<struct winapi::sockaddr_in *>(&SocketAddr);
    *PortPtr = winapi::ntohs(SocketAddrv4->sin_port);
    std::memcpy(AddressPtr, &(SocketAddrv4->sin_addr.s_addr), AddrLen);
  } else if (SocketAddr.ss_family == winapi::AF_INET6) {
    *AddrTypePtr = 6;
    auto SocketAddrv6 =
        reinterpret_cast<struct winapi::sockaddr_in6 *>(&SocketAddr);

    *PortPtr = winapi::ntohs(SocketAddrv6->sin6_port);
    std::memcpy(AddressPtr, &(SocketAddrv6->sin6_addr.s6_addr), AddrLen);
  } else {
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }

  return {};
}

WasiExpect<void> INode::sockGetLocalAddrV2(uint8_t *AddressBufPtr,
                                           uint32_t *PortPtr) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  auto *UA = reinterpret_cast<UniversalAddress *>(AddressBufPtr);

  struct winapi::sockaddr_storage SocketAddr;
  winapi::socklen_t Slen = sizeof(SocketAddr);
  std::memset(&SocketAddr, 0, sizeof(SocketAddr));

  if (auto Res = winapi::getsockname(
          toSocket(Handle),
          reinterpret_cast<struct winapi::sockaddr *>(&SocketAddr), &Slen);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  if (SocketAddr.ss_family == winapi::AF_INET) {
    auto SocketAddrv4 =
        reinterpret_cast<struct winapi::sockaddr_in *>(&SocketAddr);

    UA->AddressFamily = __WASI_ADDRESS_FAMILY_INET4;
    *PortPtr = winapi::ntohs(SocketAddrv4->sin_port);
    std::memcpy(UA->Address, &SocketAddrv4->sin_addr,
                std::min(sizeof(struct winapi::in_addr), sizeof(UA->Address)));
  } else if (SocketAddr.ss_family == winapi::AF_INET6) {
    auto SocketAddrv6 =
        reinterpret_cast<struct winapi::sockaddr_in6 *>(&SocketAddr);

    UA->AddressFamily = __WASI_ADDRESS_FAMILY_INET6;
    *PortPtr = winapi::ntohs(SocketAddrv6->sin6_port);
    std::memcpy(UA->Address, &SocketAddrv6->sin6_addr,
                std::min(sizeof(struct winapi::in6_addr), sizeof(UA->Address)));
  } else {
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }

  return {};
}

WasiExpect<void> INode::sockGetPeerAddrV1(uint8_t *, uint32_t *,
                                          uint32_t *) const noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> INode::sockGetPeerAddrV2(uint8_t *AddressBufPtr,
                                          uint32_t *PortPtr) const noexcept {
  if (auto Res = detail::ensureWSAStartup(); unlikely(!Res)) {
    return WasiUnexpect(Res);
  }

  auto *UA = reinterpret_cast<UniversalAddress *>(AddressBufPtr);

  struct winapi::sockaddr_storage SocketAddr;
  winapi::socklen_t Slen = sizeof(SocketAddr);
  std::memset(&SocketAddr, 0, sizeof(SocketAddr));

  if (auto Res = winapi::getpeername(
          toSocket(Handle),
          reinterpret_cast<struct winapi::sockaddr *>(&SocketAddr), &Slen);
      unlikely(Res == winapi::SOCKET_ERROR_)) {
    return WasiUnexpect(detail::fromWSALastError());
  }

  if (SocketAddr.ss_family == winapi::AF_INET) {
    auto SocketAddrv4 =
        reinterpret_cast<struct winapi::sockaddr_in *>(&SocketAddr);

    UA->AddressFamily = __WASI_ADDRESS_FAMILY_INET4;
    *PortPtr = ntohs(SocketAddrv4->sin_port);
    std::memcpy(UA->Address, &SocketAddrv4->sin_addr,
                std::min(sizeof(struct winapi::in_addr), sizeof(UA->Address)));
  } else if (SocketAddr.ss_family == winapi::AF_INET6) {
    auto SocketAddrv6 =
        reinterpret_cast<struct winapi::sockaddr_in6 *>(&SocketAddr);

    UA->AddressFamily = __WASI_ADDRESS_FAMILY_INET6;
    *PortPtr = ntohs(SocketAddrv6->sin6_port);
    std::memcpy(UA->Address, &SocketAddrv6->sin6_addr,
                std::min(sizeof(struct winapi::in6_addr), sizeof(UA->Address)));
  } else {
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }
  return {};
}

WasiExpect<__wasi_filetype_t> INode::filetype() const noexcept {
  if (auto Res = getAttribute(Handle); unlikely(!Res)) {
    return WasiUnexpect(Res);
  } else {
    return fromFileType(*Res, Handle);
  }
}

bool INode::isDirectory() const noexcept {
  if (auto Res = getAttribute(Handle); unlikely(!Res)) {
    return false;
  } else {
    return (*Res) & winapi::FILE_ATTRIBUTE_DIRECTORY_;
  }
}

bool INode::isSymlink() const noexcept {
  if (auto Res = getAttribute(Handle); unlikely(!Res)) {
    return false;
  } else {
    return (*Res) & winapi::FILE_ATTRIBUTE_REPARSE_POINT_;
  }
}

WasiExpect<__wasi_filesize_t> INode::filesize() const noexcept {
  if (winapi::LARGE_INTEGER_ FileSize;
      unlikely(!winapi::GetFileSizeEx(Handle, &FileSize))) {
    return WasiUnexpect(detail::fromLastError(winapi::GetLastError()));
  } else {
    return static_cast<__wasi_filesize_t>(FileSize.QuadPart);
  }
}

bool INode::canBrowse() const noexcept { return false; }

Poller::Poller(__wasi_size_t Count) { Events.reserve(Count); }

WasiExpect<void> Poller::clock(__wasi_clockid_t, __wasi_timestamp_t,
                               __wasi_timestamp_t, __wasi_subclockflags_t,
                               __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::read(const INode &, __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::write(const INode &, __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::wait(CallbackType) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

Epoller::Epoller(__wasi_size_t Count, int) { Events.reserve(Count); }

WasiExpect<void> Epoller::clock(__wasi_clockid_t, __wasi_timestamp_t,
                                __wasi_timestamp_t, __wasi_subclockflags_t,
                                __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::read(const INode &, __wasi_userdata_t,
                               std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::write(const INode &, __wasi_userdata_t,
                                std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::wait(CallbackType,
                               std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

} // namespace WASI
} // namespace Host
} // namespace WasmEdge

#endif
