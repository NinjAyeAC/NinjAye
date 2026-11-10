# Publishing checklist

This directory is a standalone Git repository.

## Local repository

```powershell
Set-Location .\NinjAye
git init -b main
git add .
git status
git commit -m "Initial NinjAye release"
```

Before committing, verify:

```powershell
git ls-files
git check-ignore -v .\config\ninjaye-dev-private.pem
git check-ignore -v .\.env
git check-ignore -v .\build\
```

The file list must not contain PEM files, `.env`, build output, logs, game
binaries, crash dumps or captured session data.

## GitHub repository

Create an empty repository, then configure the remote:

```powershell
git remote add origin https://github.com/<owner>/<repository>.git
git push -u origin main
```

Suggested description:

> Client protection platform with native C++ DLL/SDK, challenge
> verification, detection pipeline, ASP.NET Core API and PostgreSQL storage.

Suggested topics:

```text
anti-cheat
windows
cpp
csharp
aspnet-core
postgresql
reverse-engineering
security-research
```

## Release settings

1. Confirm that the selected license covers all repository material.
2. Enable private vulnerability reporting.
3. Protect `main` and require the `ci` workflow.
4. Keep real deployment keys in the server's secret manager.
5. Publish only source and documentation; never publish local development
   keys or real telemetry.
