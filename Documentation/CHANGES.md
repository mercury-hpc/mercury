## Summary

This new version brings both bug fixes and feature updates to mercury.

## New features

- __[NA]__
  - Remove `NA_DEFAULT_PLUGIN_PATH` and use `NA_PLUGIN_RELATIVE_PATH` instead
    - Use relative path for NA plugin search
    - Calculate relative path at build time and use it at runtime to find the plugin directory
- __[NA OFI]__
  - Fix compatibility with libfabric 2.0
  - Pass down NA flags for firewall support in prov/tcp
    - Indicate if client bulk address is behind firewall by using address deserialization callback functions
- __[HG/NA perf]__
  - Add `-N` option to keep perf server up after client exits
  - Remove barrier by default in perf loop and add `--barrier` as optional option to use barrier again
    - Add min/max measurements when barrier is not used
  - Print only first and last targets when reading config
  - Re-organize and clean up printed fields
- __[HG Util]__
  - Add `fatal` and `info` log levels
  - This replaces the previous fatal log subsys, default log level is now `fatal`

## Bug fixes

- __[HG]__
  - Ensure that one-way RPCs can overflow
    - Use existing ack notifications to ensure send buffer remains available
  - Fix handling of multi-recv operations returning NULL buffers and repost multi-recv buffer if released
  - Fix possible erroneous refcount when bulk create/transfer fails
  - Enable diagnostic counters outside of debug builds
  - Enable HG proc overflow when using XDR
    - Fix hg_proc_save_ptr() error handling and allocation with XDR
    - Multiple proc fixes for XDR encoding
- __[NA]__
  - Fix plugin scan to continue if one plugin cannot load
- __[NA OFI]__
  - Check against `FI_REMOTE_CQ_DATA` before accessing `cq_event->data`
  - Fix case of `FI_MULTI_RECV` event returned without buffer
  - Fix completion of multi-recv cancelation with prov/cxi
    - Only complete in error path when `FI_MULTI_RECV` is set
    - Multi-recv operations may still be used even after an error has occurred
  - Improve logging of canceled events
  - Add missing op type from op completed error log
  - Fix compile error on older prov/cxi platforms
  - Attempt to use `ip_subnet` with `FI_SOCKADDR_IN` format
- __[NA BMI]__
  - Do not BMI_initialize() servers with address `0.0.0.0` and detect address to use
- __[HG/NA Perf]__
  - Fix potential race when re-using exp op ID
  - Add spin_flag to prevent from excessively sleeping
    - Reduce overhead of hg_poll_wait()
- __[HG util]__
  - Fix global buffer overflow in `hg_log_outlet_active`
  - Fix error return of `hg_mem_pool_extend()`
- __[CMake]__
  - Fix tirpc to be an external dependency

## :warning: Known Issues

- __[NA OFI]__
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE` to be set.
