## Summary

This version brings bug fixes and updates to our v2.0.0 release.

## New features

<span style="color:lightblue">Added in rc2</span>

- __[HG Test]__
    - Perf test now supports multi-client / multi-server workloads
    - Add `BUILD_TESTING_UNIT` and `BUILD_TESTING_PERF` CMake options
- __[NA OFI]__
    - Add support for libfabric log redirection
        - Requires libfabric >= 1.16.0, disabled if FI_LOG_LEVEL is set
        - Add `libfabric` log subsys (off by default)
        - Bump FI_VERSION to 1.13 when log redirection is supported
- __[HG util]__
    - Add HG_LOG_WRITE_FUNC() macro to pass func/line info
    - Add also `module` / `no_return` parameters to hg_log_write()
    - Remove `HG_ATOMIC_VAR_INIT` (deprecated)

---
<span style="color:lightblue">Added in rc1

- __[HG]__
    - Add support for multi-recv operations (OFI plugin only)
        - Currently disable multi-recv when auto SM is on
        - Posted recv operations are in that case decoupled from pool of RPC handles
        - Add `release_input_early` init info flag to attempt to release input buffers early once input is decoded
        - Add `HG_Release_input_buf()` to manually release input buffer.
        - Add also `no_multi_recv` init info option to force disabling multi-recv
    - Make use of subsys logs (`cls`, `ctx`, `addr`, `rpc`, `poll`) to control log output
    - Add init info struct versioning
- __[HG bulk]__
    - Update to new logging system through `bulk` subsys log.
- __[HG proc]__
    - Update to new logging system through `proc` subsys log.
- __[HG Test]__
    - Refactor tests to separate perf tests from unit tests
    - Add NA/HG test common library
    - Add `hg_rate` / `hg_bw_write` and `hg_bw_read` perf tests
    - Install perf tests if `BUILD_TESTING` is `ON`
- __[NA]__
    - Add support for multi-recv operations
        - Add `NA_Msg_multi_recv_unexpected()` and `na_cb_info_multi_recv_unexpected` cb info
        - Add `flags` parameter to `NA_Op_create()` and `NA_Msg_buf_alloc()`
        - Add `NA_Has_opt_feature()` to query multi recv capability
    - Remove int return type from NA callbacks and return void
    - Remove unused `timeout` parameter from `NA_Trigger()`
    - `NA_Addr_free()` / `NA_Mem_handle_free()` and `NA_Op_destroy()` now return void
    - `na_mem_handle_t` and `na_addr_t` types to no longer include pointer type
    - Add `NA_PLUGIN_PATH` env variable to optionally control plugin loading path
    - Add `NA_DEFAULT_PLUGIN_PATH` CMake option to control default plugin path (default is lib install path)
    - Add `NA_USE_DYNAMIC_PLUGINS` CMake option (OFF by default)
    - Bump NA library version to 4.0.0
- __[NA OFI]__
    - Add support for multi-recv operations and use `FI_MSG`
    - Allocate multi-recv buffers using hugepages when available
    - Switch to using `fi_senddata()` with immediate data for unexpected msgs
        - `NA_OFI_UNEXPECTED_TAG_MSG` can be set to switch back to former behavior that uses tagged messages instead
    - Remove support for deprecated `psm` provider
    - Control CQ interrupt signaling with `FI_AFFINITY` (only used if thread is bound to a single CPU ID)
    - Enable `cxi` provider to use `FI_WAIT_FD`
    - Add `NA_OFI_OP_RETRY_TIMEOUT` and `NA_OFI_OP_RETRY_PERIOD`
        - Once `NA_OFI_OP_RETRY_TIMEOUT` milliseconds elapse, retry is stopped and operation is aborted (default is 120000ms)
        - When `NA_OFI_OP_RETRY_PERIOD` is set, operations are retried only every `NA_OFI_OP_RETRY_PERIOD` milliseconds (default is 0)
    - Add support for `tcp` with and without `ofi_rxm`
        - `tcp` defaults to `tcp;ofi_rxm` for libfabric < 1.18
    - Enable plugin to be built as a dynamic plugin
- __[NA UCX]__
    - Attempt to disable UCX backtrace if `UCX_HANDLE_ERRORS` is not set
    - Add support for `UCP_EP_PARAM_FIELD_LOCAL_SOCK_ADDR`
        - With UCX >= 1.13 local src address information can now be specified on client to use specific interface and port
    - Set `CM_REUSEADDR` by default to enable reuse of existing listener addr after a listener exits abnormally
    - Attempt to reconnect EP if disconnected
        - This concerns cases where a peer would have reappeared after a previous disconnection
    - Enable plugin to be built as a dynamic plugin
- __[NA Test]__
    - Update NA test perf to use multi-recv feature
    - Update perf test to use hugepages
    - Add support for multi-targets and add lookup test
    - Install perf tests if `BUILD_TESTING` is `ON`
- __[HG util]__
    - Change return type of `hg_time_less()` to be `bool`
    - Add support for hugepage allocations
    - Use `isb` for `cpu_spinwait` on `aarch64`
    - Add `mercury_dl` to support dynamically loaded modules
    - Bump HG util version to 4.0.0

## Bug fixes

<span style="color:lightblue">Added in rc3</span>

- __[NA OFI]__
    - Log redirection requires libfabric >= 1.16.0

<span style="color:lightblue">Added in rc2</span>

- __[HG/NA]__
    - Ensure init info version is compatible
- __[NA OFI]__
    - Fix handling of extra caps to not always follow advertised caps
    - Pass `FI_COMPLETION` to RMA ops as flag is currently not ignored (`prov/opx` tmp fix)
- __[CMake]__
    - Ensure `VERSION`/`SOVERSION` is not set on `MODULE` libraries
    - Allow for in-source builds (RPM support)
    - Add missing `DL` lib dependency
    - Fix object target linking on CMake < 3.12
    - Ensure we build with PIC and PIE when available

---
<span style="color:lightblue">Added in rc1

- __[HG]__
    - Clean up and refactoring fixes
    - Fix race condition in `hg_core_forward` with debug enabled
    - Simplify RPC map and fix hashing for RPC IDs larger than 32-bit integer
    - Refactor context pools and cleanup
    - Fix potential leak on ack buffer
    - Ensure list of created RPC handles is empty before closing context
    - Bump pre-allocated requests to 512 to make use of 2M hugepages
    - Add extra error checking to prevent class mismatch
    - Fix potential race when sending one-way RPCs to ourself
- __[HG Bulk]__
    - Add extra error checking to prevent class mismatch
- __[HG Test]__
    - Refactor `test_rpc` to correctly handle timeout return values
- __[NA OFI]__
    - Force `sockets` provider to use shared domains
        - This prevents a performance regression when multiple classes are being used (`FI_THREAD_DOMAIN` is therefore disabled for this provider)
    - Refactor unexpected and expected sends, retry of OFI operations, handling of RMA operations
    - Always include `FI_DIRECTED_RECV` in primary caps
    - Remove `NA_OFI_SOURCE_MSG` flag that was matching `FI_SOURCE_ERR`
    - Fix potential refcount race when sharing domains
    - Check domain's optimal MR count if non-zero
    - Fix potential double free of src_addr info
    - Refactor auth key parsing code to build without extension headers
    - Merge latest changes required for `opx` provider enablement
- __[NA SM]__
    -  Fix handling of 0-size messages when no receive has been posted
- __[NA UCX]__
    - Fix handling of UCS return types to match NA types
- __[NA BMI]__
    - Clean up and fix some coverity warnings
- __[NA MPI]__
    - Clean up and fix some coverity warnings
- __[HG util]__
    - Clean up logging and set log root to `hg_all`
        - `hg_all` subsys can now be set to turn on logging in all subsystems
    - Set log subsys to `hg_all` if log level env is set
    - Fixes to support WIN32 builds

## :warning: Known Issues

- __[NA OFI]__
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE` to be set.
