# Detection coverage

Detection codes are stable numeric identifiers used by the NinjAye report and
cache transports. A code is emitted only when its local predicate succeeds.

## Report families

| Code | Family | Current producer |
| --- | --- | --- |
| `0x05` | private region numeric fields | `VirtualQuery` region scan |
| `0x19` | private executable region | writable/executable region scan |
| `0x81` | queued report task | queue state observation |
| `0x99` | startup worker | profile-gated shadow-name observation |
| `0xB2` | graphics vtable method | fail closed |
| `0xB3` | graphics vtable address | fail closed |
| `0xB4` | execution breakpoint | debug-register scan |
| `0xB5` | recorded breakpoint address | breakpoint summary |
| `0xB8` | process record | fail closed |
| `0xB9` | process detail | fail closed |
| `0xC1` | injected mouse input | input telemetry state |
| `0xC2` | injected keyboard input | input telemetry state |
| `0xC3` | low interval variation | input interval analysis |
| `0xC4` | continuous input window | continuous-window analysis |
| `0xC5` | repeated input sequence | sequence analysis |
| `0xC6` | low input code mean | keyboard-code analysis |
| `0xD7` | mixed injected input | injected/clear distribution |
| `0xD8` | keyboard interval distribution | interval analysis |
| `0xD9` | injected/clear divergence | split-population analysis |
| `0xDF` | channel statistics | per-channel capture report |
| `0xE0` | periodic channel input | interval statistics |
| `0xE1` | duration statistics | press-duration statistics |
| `0xE2` | short duration pressure | short-duration ratio |
| `0xE3` | macro composite | combined input verdict |

The `0xC1..0xE3` families include channel and injected-state groups. No
baseline or zero-sample row is appended. Findings use a positive severity.

## Communication channels

Structured reports use multipart MPNE `/upload.php`. Small timing records use
the exact 60-byte `/event.php` shape.

| Type | Code | Meaning |
| ---: | ---: | --- |
| `0x01` | `0x17A` | callback registry missing |
| `0x02` | `0x182` | callback registry incomplete |
| `0x03` | `0x1A0` | status transport failure |
| `0x06` | `0x234` | repeated challenge |
| `0x07` | `0x244` | module CRC mismatch |
| `0x09` | `0x282` | status result/validation bits |
| `0x10` | `0x1ED` | thread summary |
| `0x10` | `0x22D` | short-period episode aggregate |
| `0x10` | `0x2B1` | confirmed suspended thread |

`0x555` is reserved but not emitted because NinjAye does not have a complete
validated process-handle predicate.

## Composite groups

`detection_groups.h` contains 75 fixed group rules. After direct detections are
collected, group requirements are evaluated to a fixed point. A matched group
emits its numeric result and records its member IDs in `details.groupRule`.

`detection_policy.h` supplies the mask, limit and points value for every
emitted family. The transport exposes the points value as severity/confidence;
the local policy remains available to the client.

## Input capture

The DLL installs `WH_KEYBOARD_LL` and `WH_MOUSE_LL` hooks on a dedicated thread.
Capture keeps bounded keyboard and mouse rings, QPC/tick timestamps, foreground
generation, injected-state flags, movement counts and press durations. Every
hook event is forwarded unchanged.

Raw text is not included in reports. Input reports contain numeric aggregates
and the numeric key-code sequence required by `0xC5`.

## Thread handling

`NtQueryInformationThread` class `0x28` supplies thread state and wait reason.
Class `0x23` supplies the suspend count. A matching thread must remain in the
validated state for at least 1500 ms and be observed at least twice before it
emits `0x2B1`.

Four short episodes within 60 seconds can emit `0x22D`, subject to a 60-second
cooldown. At least four matching threads can emit `0x1ED`.

## Hardware breakpoints

Each other thread is queried with `GetThreadContext` and
`CONTEXT_DEBUG_REGISTERS`. Slots with enabled execution breakpoints emit
`0xB4`; the summary emits `0xB5`.

## Fail-closed boundaries

Unimplemented or incomplete families do not emit placeholder findings. The
current fail-closed set includes graphics-vtable, process-record/detail,
alternate process analysis, process-handle and unfinished protected region
subchecks.

The clean-run validation emits no report or cache record without a matching
predicate.
