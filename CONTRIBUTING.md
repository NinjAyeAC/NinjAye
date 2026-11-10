# Contributing

## Before opening a pull request

1. Create a focused branch.
2. Keep third-party binaries, captures and credentials out of the change.
3. Use synthetic data in tests and documentation.
4. Preserve the documented protocol behavior or document an intentional
   fail-closed boundary.
5. Run the relevant build, formatting and integration checks.

## Native C++ style

- C++20.
- Lowercase `snake_case` identifiers.
- Allman brace style.
- Four-space indentation.
- Stable numeric error codes instead of diagnostic strings at protocol
  boundaries.
- Visual Studio filters use lowercase `snake_case` names.

## C# style

Follow the official Microsoft/.NET conventions:

- `PascalCase` for types, methods, properties and files;
- `camelCase` for parameters and local variables;
- `_camelCase` for private fields;
- one public top-level type per file;
- nullable reference types enabled.

The server enforces formatting with:

```powershell
dotnet format .\server\NinjAye.Server\NinjAye.Server.csproj --verify-no-changes --severity warn
```

## Validation

```powershell
dotnet build .\server\NinjAye.Server\NinjAye.Server.csproj -c Release
msbuild .\client\sdk\example\NinjAye.Example.vcxproj /m `
  /p:Configuration=Release /p:Platform=x64 `
  "/p:SolutionDir=$((Resolve-Path .).Path.TrimEnd('\') + '\')"
msbuild .\client\sdk\example\NinjAye.Example.vcxproj /m `
  /p:Configuration=Release /p:Platform=Win32 `
  "/p:SolutionDir=$((Resolve-Path .).Path.TrimEnd('\') + '\')"
pwsh .\tests\run_end_to_end.ps1
```

Describe the behavior changed, why it changed, and which checks passed. A pull
request should not include generated keys, `.env`, build output or unrelated
compatibility material.

## Licensing

The repository currently has no open-source license. Do not copy third-party
code, binaries or third-party assets unless their ownership and redistribution
terms are documented.
