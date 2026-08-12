# Root Cause Analysis and Fix Plan

## I. Root Cause Analysis

### Problem Essence
F-Stack's config.ini does not support arbitrary DPDK EAL startup parameter passthrough. Users wanting to pass devargs (e.g., `scalar_enable=1`) face:

1. `allow` config item uses commas to separate multiple PCI devices (`lib/ff_config.c:1191`), cannot append devargs.
2. No generic EAL parameter passthrough mechanism; can only modify `lib/ff_config.c` source code manually.

### Code Tracing
- `lib/ff_config.c:1151-1308`: `dpdk_args_setup()` builds EAL parameters in fixed order, no extension point.
- `lib/ff_config.h:35`: `DPDK_CONFIG_NUM 16`, dpdk_argv array upper limit; fixed parameters already occupy many slots.

## II. Fix Plan

### New `extra_eal_args` Config Item

Added `extra_eal_args` in `[dpdk]` section, space-separated multiple EAL parameters, appended as-is to `dpdk_argv[]` end.

### Change Details

#### 1. `lib/ff_config.h:34-35` — Increase DPDK_CONFIG_NUM
```c
// dpdk argc, argv, max argc: 32, member of dpdk_config
#define DPDK_CONFIG_NUM 32
```
Increased from 16 to 32, reserving space for user custom parameters. M1 sub-agent confirmed no hardcoded 16 dependencies; all references auto-follow through macro (including test stub files).

#### 2. `lib/ff_config.h:285-288` — New Field
```c
        /* pci whiltelist */
        char *allow;

        /* extra DPDK EAL args, appended to rte_eal_init argv */
        char *extra_eal_args;

        int nb_channel;
```

#### 3. `lib/ff_config.c:1044-1047` — New Parsing
```c
    } else if (MATCH("dpdk", "allow")) {
        pconfig->dpdk.allow = strdup(value);
    } else if (MATCH("dpdk", "extra_eal_args")) {
        pconfig->dpdk.extra_eal_args = strdup(value);
    } else if (MATCH("dpdk", "port_list")) {
```

#### 4. `lib/ff_config.c:1284-1298` — dpdk_args_setup Append at End
```c
    }

    if (cfg->dpdk.extra_eal_args) {
        char* token;
        char* rest = cfg->dpdk.extra_eal_args;

        while ((token = strtok_r(rest, " ", &rest))) {
            if (n >= DPDK_CONFIG_NUM) {
                printf("extra_eal_args exceed DPDK_CONFIG_NUM, truncated\n");
                break;
            }
            dpdk_argv[n++] = strdup(token);
        }
    }

    dpdk_argc = n;
```

#### 5. `lib/ff_config.c:1764-1766` — Free Logic
```c
    if (ff_global_cfg.dpdk.extra_eal_args) {
        free(ff_global_cfg.dpdk.extra_eal_args);
        ff_global_cfg.dpdk.extra_eal_args = NULL;
    }
```

#### 6. `config.ini:74-78` — Config Item Comment
```ini
#allow=02:00.0,03:00.0

# Extra DPDK EAL args, space-separated, appended to rte_eal_init() argv.
# e.g. extra_eal_args=--allow=02:00.0,scalar_enable=1
# e.g. extra_eal_args=--log-level=pmd:8 --iova-mode=pa
#extra_eal_args=
```

## III. Backward Compatibility

| Scenario | Behavior |
|----------|---------|
| No extra_eal_args configured | No impact (NULL, no parameters appended) |
| extra_eal_args configured | Parameters appended to dpdk_argv end |
| Parameter with same name as F-Stack auto-built | DPDK EAL later overrides earlier (expected behavior) |
| Parameters exceeding DPDK_CONFIG_NUM | Prints warning and truncates (prevents overflow) |

## IV. Security Boundary

1. **Pure passthrough**: extra_eal_args does not participate in F-Stack internal logic parsing; only passed through to DPDK.
2. **User responsibility**: Users must ensure correct parameter format (e.g., `--device` is not a DPDK EAL parameter; use `--allow`). F-Stack does not impose whitelist restrictions, consistent with DPDK native behavior.
3. **Upper bound protection**: `n >= DPDK_CONFIG_NUM` check prevents array overflow.
