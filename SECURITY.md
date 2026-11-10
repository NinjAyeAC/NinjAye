# Security policy

## Supported versions

NinjAye is under active development. Security fixes are applied
to the current `main` branch only.

## Reporting a vulnerability

Do not open a public issue for a vulnerability, a leaked credential or a
capture containing user data. Use GitHub's private **Report a vulnerability**
flow in the repository Security tab. Include:

- affected component and revision;
- a concise impact statement;
- reproduction steps using synthetic data;
- relevant logs with tokens, usernames and machine identifiers removed;
- a proposed fix when available.

Do not test against systems or accounts you do not own or have permission to
use. Do not upload original game binaries, live session captures, private keys,
bearer tokens or personal information.

## Repository secret policy

The repository must not contain:

- RSA private keys or signing keys;
- production database passwords;
- reusable bearer tokens;
- third-party Authorization values;
- third-party protection-server endpoints;
- real client or player data.

The normal development bootstrap generates an RSA-2048 pair and a random local
PostgreSQL password. These files are ignored by Git and must remain local.

If a secret is committed, remove it from the working tree, rotate it, and purge
it from Git history before publishing the repository.
