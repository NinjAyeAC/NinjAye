# NinjAye.dll

The DLL is written in C++20 and uses snake_case identifiers with Allman braces.

Exports are defined in `include/ninjaye.h`.

Open the root `NinjAye.sln` in Visual Studio 2022 and build
`Release|x64` or `Release|Win32`. The project targets the v143 toolset.

Output:

```text
build/<platform>/<configuration>/NinjAye.dll
build/<platform>/<configuration>/NinjAye.pdb
build/<platform>/<configuration>/NinjAye.lib
```

The DLL uses no third-party credential or fixed remote endpoint. Enrollment
tokens and install IDs are generated in memory on every process start. Nothing
is written to disk or reused by a later process.

The project generates a local RSA development key pair and an ignored
`src/ninjaye_public_key.h` before compilation. The private PEM stays in the
local `config` directory and must never be committed.
