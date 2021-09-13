## Summary

This version brings bug fixes and updates to our v2.0.0 release.

## New features

- __[NA UCX]__
    - Add initial support for UCX. As opposed to other plugins, the UCX plugin is able through the `ucx+all` init string to decide on which protocol to use.
- __[NA]__
    - Add `thread_mode` to NA init options and add `NA_THREAD_MODE_SINGLE` to relax thread-safety requirements.
    - Add `na_cb_info_recv_expected` to return `actual_buf_size`.
    - Add `na_cb_type_to_string()` to convert callback enum type to printable string.
- __[NA IP]__
    - Add `na_ip_check_interface()` routine that can be used by plugins to select IP interface to use.
- __[HG util]__
    - Add `hg_mem_header_alloc()`/`free()` calls to allocate buffers with a preceding header.
    - Add thread annotation module for thread safety analysis.
    - Add `mercury_mem_pool` memory pool to facilitate allocation and memory registration of a pool of buffers.
    - Enable format argument checking on logging functions.
    - Add `hg_time_from_ms()` and `hg_time_to_ms()` for time conversion to ms.
- __[HG bulk]__
    - Return transfer size `size` through `hg_cb_info` and `hg_cb_info_bulk`.

## Bug fixes

- __[NA OFI]__
    - Fix handling of completion queue events and completion of retried operations that fail.
    - Fix progress loop to reduce time calls.
- __[HG util]__
    - Prevent use of `CLOCK_MONOTONIC_COARSE` on PPC platforms and default to `CLOCK_MONOTONIC`.
    - Fix debug logs that were not freed at exit.
    - Remove return value of mutex lock/unlock routines.
    - Fix log subsys to prevent setting duplicates.
- __[HG/HG util/NA]__
    - Fix thread safety warnings and potential thread locking issues.
    - Fix log level set routines that were not enabling the underlying log sub-system.
- __[HG bulk]__
    - Fix erroneous call to `NA_Mem_deregister()` when handle is deserialized.
    - Correctly mark op as canceled if canceled from NA.
- __[HG Core]__
    - Correctly print HG handle debug information.
    - In short responses like ACKs, leave room at the front of a buffer for
    the NA header, and expect the header to be present.

## :warning: Known Issues

- __[NA OFI]__
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE` to be set.
    - [tcp;ofi_rxm] Remains unstable, use `sockets` as a fallback in case of issues.
        - __Please note that libfabric v1.13.0 and v1.13.1 have address management issues with that provider. We do not recommend upgrading to these versions at the moment.__
- __[NA UCX]__
    - `NA_Addr_to_string()` cannot be used on non-listening processes to convert a self-address to a string.
    - Serialization of addresses is currently not supported and will be supported in future UCX releases.
