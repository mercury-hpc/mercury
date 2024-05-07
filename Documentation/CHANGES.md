## Summary

This is a preview release of the v2.4.0 release.

## New features

<span style="color:blue">Added in rc2</span>

- __[NA OFI]__
    - Add support for `FI_AV_AUTH_KEY` (requires libfabric >= 1.20)
        - Add runtime check for cxi provider version
        - Setting multiple auth keys disables `FI_DIRECTED_RECV`
        - Separate opening of AV and auth key insertion
        - Parse auth key range when `FI_AV_AUTH_KEY` is available
        - Encode/decode auth key when serializing addrs
    - Add support for `FI_AV_USER_ID`
    - Clean up handling of `FI_SOURCE_ERR`
    - Remove support of `FI_SOURCE` w/o `FI_SOURCE_ERR`
    - Add support for new CXI address format

---
<span style="color:blue">Added in rc1</span>

- __[NA]__
    - Add init info version compatibility wrappers
    - Bump NA version to v4.1.0
    - Add support for `traffic_class` init info (only supported by ofi plugin)
- __[HG/NA Perf Test]__
    - Add `-f`/`--hostfile` option to select hostfile to write to / read from
    - Add `-T`/`--tclass` option to select trafic class
    - Autodetect MPI implementation in perf utilities
        - MPI can now be autodetected and dynamically loaded in utilities, even if `MERCURY_TESTING_ENABLE_PARALLEL` was turned off. If `MERCURY_TESTING_ENABLE_PARALLEL` is turned on, tests remain manually linked against MPI as they used to be.
- __[NA OFI]__
    - Attempt to distribute multi-NIC domains based on selected CPU ID
    - Support selection of traffic classes (single class per NA class)

## Bug fixes

<span style="color:blue">Added in rc2</span>

- __[HG Util]__
    - Use destructor to free log outlets
- __[NA]__
    - Fix missing free of dynamic plugin entries
- __[NA UCX]__
    - Fix `hg_info` not filtering protocol   
        - Allow `na_ucx_get_protocol_info()` to resolve ucx tl name aliases
- __[NA OFI]__
    - Fix shm provider flags
- __[NA Test]__
    - Remove could not find MPI message

---
<span style="color:blue">Added in rc1</span>

- __[HG Util]__
    - Add missing prototype to `hg_atomic_fence()` definition
- __[NA OFI]__
    - Remove excessive MR count warning message
- __[NA Perf]__
    - Ensure perf tests wait on send completion

## :warning: Known Issues

- __[NA OFI]__
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE` to be set.
