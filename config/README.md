# NinjAye development keys

Development key material is generated locally and is never committed:

```powershell
pwsh ..\scripts\generate-dev-keys.ps1
```

The script creates:

```text
config/ninjaye-dev-private.pem
config/ninjaye-dev-public.pem
client/dll/src/ninjaye_public_key.h
```

The generated public modulus is compiled into `NinjAye.dll`; the matching
private PEM is available only to the local server process. The Visual Studio
DLL project invokes the generator automatically when either output is missing.

Docker Compose mounts the private PEM read-only at runtime. It is intentionally
excluded from the Docker image. Before a real deployment, generate a production
pair through a protected key-management process, rebuild the DLL with the new
public key and keep the private key only in the server's secret manager.

Never enable third-party keys, Authorization values or service endpoints as
fallbacks.
