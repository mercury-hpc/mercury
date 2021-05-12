## Summary

This version brings a few bug fixes and updates to our v2.0.0 release.

## New features

## Bug fixes

## :warning: Known Issues

- [NA OFI]
    - [tcp/verbs;ofi_rxm] Using more than 256 peers requires `FI_UNIVERSE_SIZE` to be set.
    - [tcp;ofi_rxm] Remains unstable, use `sockets` as a fallback in case of issues.
