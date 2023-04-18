// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

#include "common/defines.h"
#if !WASMEDGE_OS_WINDOWS
#error
#endif

#include "common/errcode.h"
#include "system/winapi.h"
#include "wasi/api.hpp"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace WasmEdge {
namespace Host {
namespace WASI {
inline namespace detail {

inline constexpr __wasi_errno_t fromErrNo(int ErrNo) noexcept {
  switch (ErrNo) {
  case 0:
    return __WASI_ERRNO_SUCCESS;
  case E2BIG:
    return __WASI_ERRNO_2BIG;
  case EACCES:
    return __WASI_ERRNO_ACCES;
  case EADDRINUSE:
    return __WASI_ERRNO_ADDRINUSE;
  case EADDRNOTAVAIL:
    return __WASI_ERRNO_ADDRNOTAVAIL;
  case EAFNOSUPPORT:
    return __WASI_ERRNO_AFNOSUPPORT;
  case EAGAIN:
    return __WASI_ERRNO_AGAIN;
  case EALREADY:
    return __WASI_ERRNO_ALREADY;
  case EBADF:
    return __WASI_ERRNO_BADF;
  case EBADMSG:
    return __WASI_ERRNO_BADMSG;
  case EBUSY:
    return __WASI_ERRNO_BUSY;
  case ECANCELED:
    return __WASI_ERRNO_CANCELED;
  case ECHILD:
    return __WASI_ERRNO_CHILD;
  case ECONNABORTED:
    return __WASI_ERRNO_CONNABORTED;
  case ECONNREFUSED:
    return __WASI_ERRNO_CONNREFUSED;
  case ECONNRESET:
    return __WASI_ERRNO_CONNRESET;
  case EDEADLK:
    return __WASI_ERRNO_DEADLK;
  case EDESTADDRREQ:
    return __WASI_ERRNO_DESTADDRREQ;
  case EDOM:
    return __WASI_ERRNO_DOM;
  case EEXIST:
    return __WASI_ERRNO_EXIST;
  case EFAULT:
    return __WASI_ERRNO_FAULT;
  case EFBIG:
    return __WASI_ERRNO_FBIG;
  case EHOSTUNREACH:
    return __WASI_ERRNO_HOSTUNREACH;
  case EIDRM:
    return __WASI_ERRNO_IDRM;
  case EILSEQ:
    return __WASI_ERRNO_ILSEQ;
  case EINPROGRESS:
    return __WASI_ERRNO_INPROGRESS;
  case EINTR:
    return __WASI_ERRNO_INTR;
  case EINVAL:
    return __WASI_ERRNO_INVAL;
  case EIO:
    return __WASI_ERRNO_IO;
  case EISCONN:
    return __WASI_ERRNO_ISCONN;
  case EISDIR:
    return __WASI_ERRNO_ISDIR;
  case ELOOP:
    return __WASI_ERRNO_LOOP;
  case EMFILE:
    return __WASI_ERRNO_MFILE;
  case EMLINK:
    return __WASI_ERRNO_MLINK;
  case EMSGSIZE:
    return __WASI_ERRNO_MSGSIZE;
  case ENAMETOOLONG:
    return __WASI_ERRNO_NAMETOOLONG;
  case ENETDOWN:
    return __WASI_ERRNO_NETDOWN;
  case ENETRESET:
    return __WASI_ERRNO_NETRESET;
  case ENETUNREACH:
    return __WASI_ERRNO_NETUNREACH;
  case ENFILE:
    return __WASI_ERRNO_NFILE;
  case ENOBUFS:
    return __WASI_ERRNO_NOBUFS;
  case ENODEV:
    return __WASI_ERRNO_NODEV;
  case ENOENT:
    return __WASI_ERRNO_NOENT;
  case ENOEXEC:
    return __WASI_ERRNO_NOEXEC;
  case ENOLCK:
    return __WASI_ERRNO_NOLCK;
  case ENOLINK:
    return __WASI_ERRNO_NOLINK;
  case ENOMEM:
    return __WASI_ERRNO_NOMEM;
  case ENOMSG:
    return __WASI_ERRNO_NOMSG;
  case ENOPROTOOPT:
    return __WASI_ERRNO_NOPROTOOPT;
  case ENOSPC:
    return __WASI_ERRNO_NOSPC;
  case ENOSYS:
    return __WASI_ERRNO_NOSYS;
  case ENOTCONN:
    return __WASI_ERRNO_NOTCONN;
  case ENOTDIR:
    return __WASI_ERRNO_NOTDIR;
  case ENOTEMPTY:
    return __WASI_ERRNO_NOTEMPTY;
  case ENOTRECOVERABLE:
    return __WASI_ERRNO_NOTRECOVERABLE;
  case ENOTSOCK:
    return __WASI_ERRNO_NOTSOCK;
  case ENOTSUP:
    return __WASI_ERRNO_NOTSUP;
  case ENOTTY:
    return __WASI_ERRNO_NOTTY;
  case ENXIO:
    return __WASI_ERRNO_NXIO;
  case EOVERFLOW:
    return __WASI_ERRNO_OVERFLOW;
  case EOWNERDEAD:
    return __WASI_ERRNO_OWNERDEAD;
  case EPERM:
    return __WASI_ERRNO_PERM;
  case EPIPE:
    return __WASI_ERRNO_PIPE;
  case EPROTO:
    return __WASI_ERRNO_PROTO;
  case EPROTONOSUPPORT:
    return __WASI_ERRNO_PROTONOSUPPORT;
  case EPROTOTYPE:
    return __WASI_ERRNO_PROTOTYPE;
  case ERANGE:
    return __WASI_ERRNO_RANGE;
  case EROFS:
    return __WASI_ERRNO_ROFS;
  case ESPIPE:
    return __WASI_ERRNO_SPIPE;
  case ESRCH:
    return __WASI_ERRNO_SRCH;
  case ETIMEDOUT:
    return __WASI_ERRNO_TIMEDOUT;
  case ETXTBSY:
    return __WASI_ERRNO_TXTBSY;
  case EXDEV:
    return __WASI_ERRNO_XDEV;
  default:
    assumingUnreachable();
  }
}

inline __wasi_errno_t fromLastError(winapi::DWORD_ Code) noexcept {
  switch (Code) {
  case winapi::ERROR_INVALID_PARAMETER_: // MultiByteToWideChar
    return __WASI_ERRNO_INVAL;
  case winapi::ERROR_SHARING_VIOLATION_: // CreateFile2
  case winapi::ERROR_PIPE_BUSY_:         // CreateFile2
    return __WASI_ERRNO_BUSY;
  case winapi::ERROR_ACCESS_DENIED_: // CreateFile2
    return __WASI_ERRNO_ACCES;
  case winapi::ERROR_ALREADY_EXISTS_: // CreateFile2
  case winapi::ERROR_FILE_EXISTS_:    // CreateFile2
    return __WASI_ERRNO_EXIST;
  case winapi::ERROR_FILE_NOT_FOUND_: // CreateFile2
    return __WASI_ERRNO_NOENT;

  case winapi::ERROR_INSUFFICIENT_BUFFER_:    // MultiByteToWideChar
  case winapi::ERROR_INVALID_FLAGS_:          // MultiByteToWideChar
  case winapi::ERROR_NO_UNICODE_TRANSLATION_: // MultiByteToWideChar
  default:
    return __WASI_ERRNO_NOSYS;
  }
}

using FiletimeDuration = std::chrono::duration<
    uint64_t,
    std::ratio_multiply<std::ratio<100, 1>, std::chrono::nanoseconds::period>>;
/// from 1601-01-01 to 1970-01-01, 134774 days
static inline constexpr const FiletimeDuration NTToUnixEpoch =
    std::chrono::seconds{134774u * 86400u};

static constexpr __wasi_timestamp_t
fromFiletime(winapi::FILETIME_ FileTime) noexcept {
  using std::chrono::duration_cast;
  using std::chrono::nanoseconds;
  winapi::ULARGE_INTEGER_ Temp = {.LowPart = FileTime.dwLowDateTime,
                                  .HighPart = FileTime.dwHighDateTime};
  auto Duration = duration_cast<nanoseconds>(FiletimeDuration{Temp.QuadPart} -
                                             NTToUnixEpoch);
  return static_cast<__wasi_timestamp_t>(Duration.count());
}

static constexpr winapi::FILETIME_
toFiletime(__wasi_timestamp_t TimeStamp) noexcept {
  using std::chrono::duration_cast;
  using std::chrono::nanoseconds;
  auto Duration =
      duration_cast<FiletimeDuration>(nanoseconds{TimeStamp}) + NTToUnixEpoch;
  winapi::ULARGE_INTEGER_ Temp = {.QuadPart = Duration.count()};
  return winapi::FILETIME_{.dwLowDateTime = Temp.LowPart,
                           .dwHighDateTime = Temp.HighPart};
}

inline __wasi_errno_t fromWSALastError() noexcept {
  switch (winapi::WSAGetLastError()) {
  case winapi::WSASYSNOTREADY_: // WSAStartup
  case winapi::WSAEWOULDBLOCK_: // closesocket
    return __WASI_ERRNO_AGAIN;
  case winapi::WSAVERNOTSUPPORTED_: // WSAStartup
    return __WASI_ERRNO_NOTSUP;
  case winapi::WSAEINPROGRESS_: // WSAStartup, socket, closesocket
    return __WASI_ERRNO_INPROGRESS;
  case winapi::WSAEPROCLIM_: // WSAStartup
    return __WASI_ERRNO_BUSY;
  case winapi::WSAEFAULT_: // WSAStartup
    return __WASI_ERRNO_FAULT;
  case winapi::WSAENETDOWN_: // socket, closesocket
    return __WASI_ERRNO_NETDOWN;
  case winapi::WSAENOTSOCK_: // closesocket
    return __WASI_ERRNO_NOTSOCK;
  case winapi::WSAEINTR_: // closesocket
    return __WASI_ERRNO_INTR;
  case winapi::WSAEAFNOSUPPORT_: // socket
    return __WASI_ERRNO_AIFAMILY;
  case winapi::WSAEMFILE_: // socket
    return __WASI_ERRNO_NFILE;
  case winapi::WSAEINVAL_: // socket
    return __WASI_ERRNO_INVAL;
  case winapi::WSAENOBUFS_: // socket
    return __WASI_ERRNO_NOBUFS;
  case winapi::WSAEPROTONOSUPPORT_: // socket
    return __WASI_ERRNO_PROTONOSUPPORT;
  case winapi::WSAEPROTOTYPE_: // socket
    return __WASI_ERRNO_PROTOTYPE;
  case winapi::WSAESOCKTNOSUPPORT_: // socket
    return __WASI_ERRNO_AISOCKTYPE;
  case winapi::WSAEINVALIDPROCTABLE_:   // socket
  case winapi::WSAEINVALIDPROVIDER_:    // socket
  case winapi::WSAEPROVIDERFAILEDINIT_: // socket
  case winapi::WSANOTINITIALISED_:      // socket, closesocket
  default:
    return __WASI_ERRNO_NOSYS;
  }
}

inline constexpr __wasi_errno_t fromWSAError(int WSAError) noexcept {
  switch (WSAError) {
  case winapi::WSATRY_AGAIN_:
    return __WASI_ERRNO_AIAGAIN;
  case winapi::WSAEINVAL_:
    return __WASI_ERRNO_AIBADFLAG;
  case winapi::WSANO_RECOVERY_:
    return __WASI_ERRNO_AIFAIL;
  case winapi::WSAEAFNOSUPPORT_:
    return __WASI_ERRNO_AIFAMILY;
  case winapi::ERROR_NOT_ENOUGH_MEMORY_:
    return __WASI_ERRNO_AIMEMORY;
  case winapi::WSAHOST_NOT_FOUND_:
    return __WASI_ERRNO_AINONAME;
  case winapi::WSATYPE_NOT_FOUND_:
    return __WASI_ERRNO_AISERVICE;
  case winapi::WSAESOCKTNOSUPPORT_:
    return __WASI_ERRNO_AISOCKTYPE;
  }
  assumingUnreachable();
}

inline __wasi_errno_t ensureWSAStartup() noexcept {
  static std::once_flag InitFlag;
  try {
    std::call_once(InitFlag, []() {
      winapi::WSADATA_ WSAData;
      if (unlikely(winapi::WSAStartup(0x0202, &WSAData) != 0)) {
        throw detail::fromWSALastError();
      }
      if (unlikely(WSAData.wVersion != 0x0202)) {
        throw __WASI_ERRNO_NOSYS;
      }
    });
    return __WASI_ERRNO_SUCCESS;
  } catch (__wasi_errno_t &Error) {
    return Error;
  }
}

inline constexpr __wasi_aiflags_t fromAIFlags(int AIFlags) noexcept {
  __wasi_aiflags_t Result = static_cast<__wasi_aiflags_t>(0);

  if (AIFlags & winapi::AI_PASSIVE) {
    Result |= __WASI_AIFLAGS_AI_PASSIVE;
  }
  if (AIFlags & winapi::AI_CANONNAME) {
    Result |= __WASI_AIFLAGS_AI_CANONNAME;
  }
  if (AIFlags & winapi::AI_NUMERICHOST) {
    Result |= __WASI_AIFLAGS_AI_NUMERICHOST;
  }
#if NTDDI_VERSION >= NTDDI_VISTA
  if (AIFlags & winapi::AI_NUMERICSERV) {
    Result |= __WASI_AIFLAGS_AI_NUMERICSERV;
  }
  if (AIFlags & winapi::AI_ALL) {
    Result |= __WASI_AIFLAGS_AI_ALL;
  }
  if (AIFlags & winapi::AI_ADDRCONFIG) {
    Result |= __WASI_AIFLAGS_AI_ADDRCONFIG;
  }
  if (AIFlags & winapi::AI_V4MAPPED) {
    Result |= __WASI_AIFLAGS_AI_V4MAPPED;
  }
#endif

  return Result;
}

inline constexpr __wasi_sock_type_t fromSockType(int SockType) noexcept {
  switch (SockType) {
  case 0:
    return __WASI_SOCK_TYPE_SOCK_ANY;
  case winapi::SOCK_DGRAM:
    return __WASI_SOCK_TYPE_SOCK_DGRAM;
  case winapi::SOCK_STREAM:
    return __WASI_SOCK_TYPE_SOCK_STREAM;
  default:
    assumingUnreachable();
  }
}

inline constexpr __wasi_protocol_t fromProtocol(int Protocol) noexcept {
  switch (Protocol) {
  case winapi::IPPROTO_IP:
    return __WASI_PROTOCOL_IPPROTO_IP;
  case winapi::IPPROTO_TCP:
    return __WASI_PROTOCOL_IPPROTO_TCP;
  case winapi::IPPROTO_UDP:
    return __WASI_PROTOCOL_IPPROTO_UDP;
  default:
    assumingUnreachable();
  }
}

inline constexpr __wasi_address_family_t
fromAddressFamily(int AddressFamily) noexcept {
  switch (AddressFamily) {
  case winapi::AF_UNSPEC:
    return __WASI_ADDRESS_FAMILY_UNSPEC;
  case winapi::AF_INET:
    return __WASI_ADDRESS_FAMILY_INET4;
  case winapi::AF_INET6:
    return __WASI_ADDRESS_FAMILY_INET6;
  default:
    assumingUnreachable();
  }
}

} // namespace detail
} // namespace WASI
} // namespace Host
} // namespace WasmEdge
