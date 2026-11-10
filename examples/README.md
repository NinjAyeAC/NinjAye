# End-to-end example

The solution contains one short native example that demonstrates both sides of
the game-packet exchange.

## Client

The native client example is:

```text
client/sdk/example/main.cpp
```

It demonstrates the complete SDK usage:

1. load `NinjAye.dll`;
2. start with the example server URL;
3. read all five ClientId variants;
4. process one 13-byte `AA` game packet;
5. call the published challenge function;
6. calculate the same challenge response in server-side code;
7. compare `challenge_reply.message` with the server expectation;
8. stop the protection before process shutdown.

The example application is split into:

```text
client.h / client.cpp  NinjAye SDK client path
server.h / server.cpp  game-server challenge creation and verification
main.cpp               complete round trip
```

The packet layout is:

```text
AA | opaque_echo[8] | message32
```

The example client changes only `message32` to the challenge result. The game
server integration must preserve the eight opaque bytes and return the same
13-byte packet shape.

The client also demonstrates the process-file pipeline: process
selection, the exact `Reserved2` digest gate, and ordered submissions of:

```text
C
C.pdb
C.dll
```

It never blindly uploads the game process or every loaded module. `/file.php`
is reached only for a selected regular process whose MD5 is allowed by the
server response.

## Packet verification path

The same example project demonstrates:

```text
game server creates AA challenge
  -> client handles it through NinjAye.dll
  -> client builds AA reply
  -> game server verifies AA header and opaque echo
```

The anti-cheat API is not part of the game server. Its backend remains the
single `NinjAye.Server` project and exposes exactly:

```text
POST /status2.php
POST /event.php
POST /upload.php
POST /file.php
```

## Run

Start `NinjAye.Server` or the complete local stack:

```powershell
docker compose up -d --build
```

Then start the native client:

```powershell
.\build\x64\Release\ninjaye_sdk_example.exe http://127.0.0.1:5088
```

For Windows x86, build `Release|Win32` and run the executable from
`build\Win32\Release`.

To exercise file submission locally, configure a controlled process-image MD5
in `Reserved2`:

```powershell
$env:NINJAYE_RESERVED2_MD5_0 = "<UPPERCASE_MD5>"
docker compose up -d --force-recreate
```
