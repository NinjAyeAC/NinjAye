# Process-selected file submission

`/file.php` is not called directly from `/status2.php`. The flow is:

```text
process worker, every 1500 ms
  -> snapshot processes
  -> apply profile-name rules and parent-PID suppression
  -> select a regular process record once
  -> read its image path and uppercase MD5
  -> apply exact Reserved2 membership
  -> submit C
  -> derive and submit C.pdb
  -> derive and submit C.dll
```

The selected profile has process flags `0`, so none of the compiled forced
process-name groups is enabled by default. The server-controlled `Reserved50`
bit `0x100` controls whether `explorer.exe` and `sihost.exe` remain suppression
barriers.

## Reserved2 gate

The gate is:

```text
digest length != 32 -> allow attempted collection
digest length == 32 -> key must exist in Reserved2
```

The comparison is exact and case-sensitive. An empty server `Reserved2` list
therefore denies normal 32-hex MD5 files. `NinjAye.Server` reads allowed keys
from `NinjAye:Reserved2` and returns rows containing `String1`.

## File action

Each accepted candidate is opened independently. Only the inclusive size
interval `5..25,000,000` reaches transport. The client submits one raw multipart
part:

```text
name=file
filename=application
Content-Type: application/octet-stream
POST /file.php
```

There is no AES/RSA/MPNE envelope for this endpoint. Submission results are
ignored by the process-collection caller.

The worker records `files_attempted` and successful `files_sent` in the public
`ninjaye_status` structure.

## Validation

Two controlled tests were run against the local backend.

Positive test with a process image and sibling PDB/DLL:

```text
FileProbe.exe  57,344 bytes  SHA-256 10649087...
FileProbe.pdb      11 bytes  SHA-256 AFD05216...
FileProbe.dll      11 bytes  SHA-256 D0E01A6C...
```

The server accepted three `/file.php` requests in the exact order `exe`, `pdb`,
`dll`, and PostgreSQL stored all three artifacts under one session.

Negative test with `Reserved2=[]`:

```text
selected process: timeout.exe
artifact count before: 2
artifact count after:  2
submission log entries: 0
```

## Compatibility boundary

The alternate-process classifier is not implemented. The worker follows the
regular process path and leaves alternate state unavailable.
