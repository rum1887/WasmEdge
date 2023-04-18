// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

#include "common/defines.h"
#if WASMEDGE_OS_WINDOWS
#include "host/wasi/clock.h"
#include "win.h"

namespace WasmEdge::Host::WASI {

WasiExpect<void> Clock::clockResGet(__wasi_clockid_t Id,
                                    __wasi_timestamp_t &Resolution) noexcept {
  switch (Id) {
  case __WASI_CLOCKID_REALTIME:
  case __WASI_CLOCKID_MONOTONIC: {
    winapi::LARGE_INTEGER_ Frequency;
    winapi::QueryPerformanceFrequency(&Frequency);
    const std::chrono::nanoseconds Result =
        std::chrono::seconds{1} / Frequency.QuadPart;
    Resolution = static_cast<__wasi_timestamp_t>(Result.count());
    return {};
  }
  default:
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }
}

WasiExpect<void> Clock::clockTimeGet(__wasi_clockid_t Id,
                                     __wasi_timestamp_t Precision
                                     [[maybe_unused]],
                                     __wasi_timestamp_t &Time) noexcept {
  switch (Id) {
  case __WASI_CLOCKID_REALTIME:
  case __WASI_CLOCKID_MONOTONIC: {
    winapi::FILETIME_ SysNow;
#if NTDDI_VERSION >= NTDDI_WIN8
    winapi::GetSystemTimePreciseAsFileTime(&SysNow);
#else
    winapi::GetSystemTimeAsFileTime(&SysNow);
#endif
    Time = detail::fromFiletime(SysNow);
    return {};
  }
  default:
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }
}

} // namespace WasmEdge::Host::WASI

#endif
