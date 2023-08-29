## Summary

This version brings bug fixes and updates to our v2.3.0 release.

## New features

- __[HG/NA Perf Test]__
    - Enable sizes to be passed using k/m/g qualifiers

## Bug fixes

- __[HG/NA]__
    - Fix potential race when checking secondary completion queue
- __[HG]__
    - Prevent multiple threads from entering `HG_Core_progress()`
        - Add `HG_ALLOW_MULTI_PROGRESS` CMake option to control behavior (`ON` by default)
        - Disable `NA_HAS_MULTI_PROGRESS` if `HG_ALLOW_MULTI_PROGRESS` is `ON`
    - Fix expected operation count for handle to be atomic
        - Expected operation count can change if extra RPC payload must be transferred
    - Let poll events remain private to HG poll wait
        - Prevent a race when multiple threads call progress and `HG_ALLOW_MULTI_PROGRESS` is `OFF`
    - Separate internal list from user created list of handles
        - Address an issue where `HG_Context_unpost()` would unnecessarily wait
- __[HG Test]__
    - Ensure affinity of class thread is set
- __[NA OFI]__
    - Fix `na_ofi_get_protocol_info()` not returning `opx` protocol
        - Refactor `na_ofi_getinfo()` to account for `NA_OFI_PROV_NULL` type
        - Ensure there are no duplicated entries
    - Refactor parsing of init info strings and fix OPX parsing
    - Simplify parsing of some address strings
    - Bump default CQ size to have a maximum depth of 128k entries
    - Remove sockets as the only provider on macOS
- __[CMake]__
    - Pass `INSTALL_NAME_DIR` through target properties
        - This fixes an issue seen on macOS where libraries would not be found using `@rpath`

## :warning: Known Issues

- __[NA OFI]__
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE`
    to be set.
