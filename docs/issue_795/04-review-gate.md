# Review Gate

## I. Review Information

- **Reviewer**: Sub-agent #2 (code-explorer), independent from main agent (code author)
- **Scope**: Code changes + documentation accuracy + backward compatibility
- **Review mode**: READ-ONLY, no file modifications

## II. Review Checklist

### 1. Code Change Correctness
- [ ] `lib/ff_config.h:34-35`: DPDK_CONFIG_NUM 16→32, comment synchronized
- [ ] `lib/ff_config.h:285-288`: extra_eal_args field definition correct (char* pointer)
- [ ] `lib/ff_config.c:1044-1047`: MATCH parsing correct (strdup pattern consistent with allow)
- [ ] `lib/ff_config.c:1284-1298`: dpdk_args_setup append logic correct (strtok_r space split + upper bound check)
- [ ] `lib/ff_config.c:1764-1766`: Free logic correct (free + set NULL pattern consistent with allow)
- [ ] `config.ini:74-78`: Config item comment correct (commented out by default)

### 2. Backward Compatibility
- [ ] No impact when extra_eal_args not configured (NULL check)
- [ ] DPDK_CONFIG_NUM increase has no side effects (M1 sub-agent confirmed no hardcoded 16 dependencies)
- [ ] Existing dpdk_args_setup fixed parameter building logic unchanged

### 3. Documentation Accuracy
- [ ] Document file:line references match actual code
- [ ] Test results match EAL argv output
- [ ] --device error format explanation accurate

### 4. config.ini Commit Constraint
- [ ] config.ini only contains feature-related comments (no local test values)
- [ ] extra_eal_args commented out by default

### 5. Code Style
- [ ] Minimal comment principle (only necessary comments)
- [ ] Preserves original code style (4-space indent, K&R, strdup/strtok_r pattern consistent)

## III. Review Conclusion

To be filled by sub-agent #2 (code-explorer) after independent review.

## IV. Risk Notes

1. **--device misuse**: Users may misuse `--device` (not a DPDK EAL parameter); documentation explains correct format is `--allow=<bdf>,<devargs>`.
2. **Parameter conflicts**: User passing same-name parameter as F-Stack auto-built (e.g., `--log-level`); DPDK EAL later overrides earlier — expected behavior.
3. **Dangerous parameters**: Users may pass parameters that break F-Stack operation (e.g., `--no-pci`); this is administrator responsibility; F-Stack does not impose whitelist restrictions.
