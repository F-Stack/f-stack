# Issue #795 Investigation Overview

## I. Issue Information

- **Issue**: [#795 Specifying devargs parameter?](https://github.com/F-Stack/f-stack/issues/795)
- **Author**: whatmatrix
- **Created**: 2024-01-22
- **Status**: open → fixed and closed

## II. Requirements Analysis

The user wants to be able to specify DPDK devargs parameters for PCI devices (e.g., `scalar_enable=1` to disable PMD vector mode) and pass them to the DPDK PMD via F-Stack configuration.

F-Stack's config.ini currently supports some DPDK EAL parameters (`allow` whitelist, `file_prefix`, `nb_vdev` virtual devices, etc.), but does not support arbitrary DPDK EAL startup parameter passthrough.

### Core Pain Point
F-Stack's `allow` configuration item uses commas to separate multiple PCI devices (`lib/ff_config.c:1191` `strtok_r(rest, ",", &rest)`), making it impossible to append devargs to allow (e.g., `allow=0000:00:09.0,scalar_enable=1` would be misinterpreted as two devices).

## III. Fix Approach

### Generic DPDK EAL Parameter Passthrough

Added a new `extra_eal_args` configuration item (in the `[dpdk]` section) that supports space-separated EAL parameters, appended as-is to the end of the `rte_eal_init()` argv.

### Configuration Example
```ini
[dpdk]
# Any DPDK EAL startup parameter, space-separated, appended to rte_eal_init() argv
extra_eal_args=--allow=0000:00:09.0,scalar_enable=1
extra_eal_args=--log-level=pmd:8 --iova-mode=pa
extra_eal_args=-d /path/to/driver.so --legacy-mem
```

### Covered Scenarios
- `--allow=<bdf>,<devargs>` — pass PMD devargs (issue #795 original request)
- `--log-level=<type>:<num>` — adjust log level
- `-d <path>` — load additional drivers
- `--iova-mode=<pa|va>` — switch IOVA mode
- `--legacy-mem` / `--single-file-segments` — memory layout adjustments
- Any other DPDK EAL supported parameter

## IV. Code Change List

| File | Change |
|------|--------|
| `lib/ff_config.h:34-35` | `DPDK_CONFIG_NUM` 16→32 + comment update |
| `lib/ff_config.h:285-288` | `ff_dpdk_cfg` new `char *extra_eal_args` field |
| `lib/ff_config.c:1044-1047` | New `MATCH("dpdk", "extra_eal_args")` parsing |
| `lib/ff_config.c:1284-1298` | `dpdk_args_setup()` end: split by space and append to `dpdk_argv[]` |
| `lib/ff_config.c:1764-1766` | Free logic for `extra_eal_args` |
| `config.ini:74-78` | New configuration item comment |

## V. Design Principles

1. **Generality**: A single configuration item covers all DPDK EAL parameters, rather than adding a separate config item for each parameter.
2. **Backward Compatibility**: Does not change existing F-Stack auto-built parameter behavior; user parameters are appended at the end.
3. **DPDK Semantics Preserved**: DPDK EAL rule is "later same-name parameter overrides earlier"; user parameters at the end can override F-Stack defaults.
4. **Security Boundary**: User parameters are only passed through to DPDK, not involved in F-Stack internal logic parsing.

## VI. Important Finding

`--device` is not a standard DPDK EAL parameter (rejected by EAL, reports `EAL: Invalid 'command line' arguments`). The correct way to pass DPDK devargs is `--allow=<bdf>,<devargs>` or `-a <bdf>,<devargs>`. This fix supports both formats via `extra_eal_args`.
