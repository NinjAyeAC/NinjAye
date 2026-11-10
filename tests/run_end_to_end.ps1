param(
    [switch]$SkipBuild,
    [switch]$SkipWin32,
    [switch]$KeepTestData,
    [switch]$NativeServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
$compose_file = Join-Path $repo_root "docker-compose.yml"
$example_project = Join-Path `
    $repo_root "client\sdk\example\NinjAye.Example.vcxproj"
$solution_directory = $repo_root.TrimEnd('\') + '\'
$initialize_script = Join-Path $repo_root "scripts\initialize-development.ps1"
$server_project = Join-Path `
    $repo_root "server\NinjAye.Server\NinjAye.Server.csproj"
$server_dll = Join-Path `
    $repo_root "server\NinjAye.Server\bin\Release\net8.0\NinjAye.Server.dll"
$example_exe = Join-Path $repo_root "build\x64\Release\ninjaye_sdk_example.exe"
$example_x86 = Join-Path $repo_root "build\Win32\Release\ninjaye_sdk_example.exe"
$example_dll = Join-Path (Split-Path -Parent $example_exe) "NinjAye.dll"
$server_url = $null
$started_at = [DateTimeOffset]::UtcNow.AddSeconds(-2)
$compose_project = "ninjaye-e2e-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$previous_server_host_port = $env:NINJAYE_SERVER_HOST_PORT
$env:NINJAYE_SERVER_HOST_PORT = "0"
$native_server_process = $null
$native_server_stdout = $null
$native_server_stderr = $null
$native_environment_names = @(
    "ASPNETCORE_URLS",
    "NinjAye__Storage",
    "NinjAye__PrivateKeyPath",
    "ConnectionStrings__Postgres",
    "PGPASSWORD",
    "PGUSER",
    "PGDATABASE"
)
$previous_native_environment = @{}
foreach ($name in $native_environment_names) {
    $previous_native_environment[$name] =
        [Environment]::GetEnvironmentVariable($name, "Process")
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message expected=$Expected actual=$Actual"
    }
}

function Assert-Match {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Value -notmatch $Pattern) {
        throw "$Message"
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($HostName, $Port)
            if ($task.Wait(1000) -and $client.Connected) {
                return
            }
        }
        catch {
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 250
    }
    throw "TCP endpoint $HostName`:$Port did not become ready."
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Write-Le16 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Destination,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][uint64]$Value
    )

    for ($index = 0; $index -lt 2; ++$index) {
        $Destination[$Offset + $index] =
            [byte](($Value -shr (8 * $index)) -band 0xFF)
    }
}

function Write-Le32 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Destination,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][uint64]$Value
    )

    for ($index = 0; $index -lt 4; ++$index) {
        $Destination[$Offset + $index] =
            [byte](($Value -shr (8 * $index)) -band 0xFF)
    }
}

function Write-Le64 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Destination,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][uint64]$Value
    )

    for ($index = 0; $index -lt 8; ++$index) {
        $Destination[$Offset + $index] =
            [byte](($Value -shr (8 * $index)) -band 0xFF)
    }
}

function Invoke-PsqlScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Sql
    )

    if ($NativeServer) {
        $psql = Join-Path $env:PGROOT "bin\psql.exe"
        $result = & $psql `
            -h 127.0.0.1 `
            -U $env:PGUSER `
            -d $env:PGDATABASE `
            -Atc $Sql
    }
    else {
        $result = & docker compose `
            -p $compose_project `
            -f $compose_file `
            exec -T postgres psql `
            -U ninjaye -d ninjaye -Atc $Sql
    }
    if ($LASTEXITCODE -ne 0) {
        throw "psql failed."
    }
    return ($result | Out-String).Trim()
}

& $initialize_script

if (-not $SkipBuild) {
    $msbuild = Join-Path $env:ProgramFiles `
        "Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
    if (-not (Test-Path -LiteralPath $msbuild)) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} `
            "Microsoft Visual Studio\Installer\vswhere.exe"
        $msbuild = & $vswhere -latest -find `
            "MSBuild\**\Bin\MSBuild.exe" |
            Select-Object -First 1
    }
    if (-not $msbuild) {
        throw "MSBuild was not found."
    }

    $toolset_override = @()
    if ($env:NINJAYE_PLATFORM_TOOLSET) {
        $toolset_override = @(
            "/p:PlatformToolset=$($env:NINJAYE_PLATFORM_TOOLSET)"
        )
    }
    & $msbuild $example_project /m /t:Build `
        /p:Configuration=Release /p:Platform=x64 `
        "/p:SolutionDir=$solution_directory" `
        @toolset_override /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Native/client build failed."
    }
    if (-not $SkipWin32) {
        & $msbuild $example_project /m /t:Build `
            /p:Configuration=Release /p:Platform=Win32 `
            "/p:SolutionDir=$solution_directory" `
            @toolset_override /v:minimal
        if ($LASTEXITCODE -ne 0) {
            throw "Win32 build failed."
        }
    }
}

Push-Location $repo_root
$test_install_id = "integration-$([Guid]::NewGuid().ToString('N'))"
$test_install_uuid = [Guid]::NewGuid()
$stack_ready = $false
try {
    if ($NativeServer) {
        if ([string]::IsNullOrWhiteSpace(
                $env:NINJAYE_TEST_POSTGRES_PASSWORD)) {
            throw "NINJAYE_TEST_POSTGRES_PASSWORD is required in native-server mode."
        }

        & dotnet build $server_project -c Release
        if ($LASTEXITCODE -ne 0) {
            throw "Server build failed."
        }

        $server_port = Get-FreeTcpPort
        $server_url = "http://127.0.0.1:$server_port"
        $env:ASPNETCORE_URLS = $server_url
        $env:NinjAye__Storage = "postgres"
        $env:NinjAye__PrivateKeyPath =
            Join-Path $repo_root "config\ninjaye-dev-private.pem"
        $env:ConnectionStrings__Postgres =
            "Host=127.0.0.1;Port=5432;Database=ninjaye_ci;" +
            "Username=ninjaye_ci;Password=$env:NINJAYE_TEST_POSTGRES_PASSWORD"
        $env:PGPASSWORD = $env:NINJAYE_TEST_POSTGRES_PASSWORD
        $env:PGUSER = "ninjaye_ci"
        $env:PGDATABASE = "ninjaye_ci"

        $native_server_stdout = Join-Path $env:TEMP `
            "ninjaye-server-$([Guid]::NewGuid().ToString('N')).out.txt"
        $native_server_stderr = Join-Path $env:TEMP `
            "ninjaye-server-$([Guid]::NewGuid().ToString('N')).err.txt"
        $native_server_process = Start-Process `
            -FilePath "dotnet" `
            -ArgumentList @($server_dll) `
            -WorkingDirectory $repo_root `
            -WindowStyle Hidden `
            -PassThru `
            -RedirectStandardOutput $native_server_stdout `
            -RedirectStandardError $native_server_stderr
        try {
            Wait-TcpPort -HostName "127.0.0.1" -Port $server_port
        }
        catch {
            $server_error = if (
                Test-Path -LiteralPath $native_server_stderr) {
                Get-Content -Raw -LiteralPath $native_server_stderr
            }
            else {
                ""
            }
            throw "$($_.Exception.Message) $server_error"
        }
        $stack_ready = $true
    }
    else {
        & docker compose -p $compose_project -f $compose_file up -d --build
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose failed."
        }
        $port_binding = & docker compose `
            -p $compose_project `
            -f $compose_file `
            port server 8080
        if ($LASTEXITCODE -ne 0 -or -not $port_binding) {
            throw "docker compose did not expose the server port."
        }
        $server_port = [int](
            ($port_binding | Select-Object -First 1).Trim().Split(":")[-1]
        )
        $server_url = "http://127.0.0.1:$server_port"
        Wait-TcpPort -HostName "127.0.0.1" -Port $server_port
        $stack_ready = $true
    }

    $stdout = Join-Path $env:TEMP `
        "ninjaye-e2e-$([Guid]::NewGuid().ToString('N')).out.txt"
    $stderr = Join-Path $env:TEMP `
        "ninjaye-e2e-$([Guid]::NewGuid().ToString('N')).err.txt"
    $process = Start-Process `
        -FilePath $example_exe `
        -ArgumentList @(
            $server_url,
            "--test-rx-region",
            "--run-once"
        ) `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr
    if (-not $process.WaitForExit(30000)) {
        Stop-Process -Id $process.Id -Force
        throw "Example client did not complete in 30 seconds."
    }
    $client_output = Get-Content -Raw -LiteralPath $stdout
    $client_error = Get-Content -Raw -LiteralPath $stderr
    if ($process.ExitCode -ne 0) {
        throw "Example client failed: $client_error"
    }

    Assert-Match $client_output "ClientId:\s+[0-9A-F]{64}" `
        "ClientId was not received."
    Assert-Match $client_output "ClientIdV2:\s+[0-9A-F]{64}" `
        "ClientIdV2 was not received."
    Assert-Match $client_output "ClientIdV3:\s+[0-9A-F]{64}" `
        "ClientIdV3 was not received."
    Assert-Match $client_output "ClientIdV4:\s+[0-9A-F]{64}" `
        "ClientIdV4 was not received."
    Assert-Match $client_output "ClientIdV5:\s+[0-9A-F]{64}" `
        "ClientIdV5 was not received."
    Assert-Match $client_output "AA packet 0x12345678 -> 0x[0-9A-F]+" `
        "Challenge callback did not return a response."
    Assert-Match $client_output "AA challenge_reply.message == expected: OK" `
        "Server-computed challenge response did not match the client reply."
    Assert-Match $client_output "AA packet server verification: OK" `
        "AA opaque echo verification failed."

    $session_count = Invoke-PsqlScalar @"
select count(*)
from ninjaye_sessions
where server_id = 1
  and dll_version = '1.2.7.7'
  and last_status_at >= '$($started_at.ToString('o'))'
  and (select count(*) from jsonb_object_keys(identities)) = 5;
"@
    if ([int]$session_count -lt 1) {
        throw "status2.php did not create a five-identity session."
    }

    $region_count = Invoke-PsqlScalar @"
select count(*)
from ninjaye_detections d
join ninjaye_reports r on r.id = d.report_id
where r.received_at >= '$($started_at.ToString('o'))'
  and d.code in (
      'protection.region.private',
      'protection.region.writable_executable'
  );
"@
    if ([int]$region_count -lt 2) {
        throw "Controlled RX region did not produce both report detections."
    }

    $dll_image_md5 =
        (Get-FileHash -LiteralPath $example_dll -Algorithm MD5).Hash
    $client_information_count = Invoke-PsqlScalar @"
select count(*)
from ninjaye_reports
where received_at >= '$($started_at.ToString('o'))'
  and (client #>> '{ClientInformation,ReportType}')::int = 1
  and client #>> '{ClientInformation,DllVersion}' = '1.2.7.7'
  and client #>> '{ClientInformation,DllBase}' ~ '^[0-9A-F]{8}$'
  and client #>> '{ClientInformation,DllImageHash}' = '$dll_image_md5'
  and client #>> '{ClientInformation,ClientIdV3_1}' is not null;
"@
    if ([int]$client_information_count -lt 1) {
        throw "Report did not contain the expected ClientInformation contract."
    }

    if (-not $SkipWin32) {
        $x86_output = & $example_x86 $server_url "--run-once" 2>&1 |
            Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "Win32 example failed: $x86_output"
        }
        Assert-Match $x86_output "AA packet 0x12345678 -> 0x[0-9A-F]+" `
            "Win32 challenge callback did not return a response."
        Assert-Match $x86_output "AA challenge_reply.message == expected: OK" `
            "Win32 server-computed challenge response mismatched."
        Assert-Match $x86_output "AA packet server verification: OK" `
            "Win32 opaque echo verification failed."
    }

    $event_token_bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $event_token = [Convert]::ToHexString($event_token_bytes)
    $token_hash = [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::ASCII.GetBytes($event_token))
    $token_hash_hex = [Convert]::ToHexString($token_hash).ToLowerInvariant()
    $installation_sql = @"
insert into ninjaye_installations
    (id, install_id, machine_label, token_hash, disabled, created_at, last_seen_at)
values
    ('$test_install_uuid', '$test_install_id', 'integration-test',
     decode('$token_hash_hex', 'hex'), false, now(), now());
"@
    $null = Invoke-PsqlScalar $installation_sql

    $seed = [uint64]0x12345678
    $file_time = [uint64]([DateTime]::UtcNow.ToFileTimeUtc())
    $ticks = [uint64][Environment]::TickCount64
    $header = [byte[]]::new(56)
    Write-Le32 $header 0 ([Convert]::ToUInt32("8D3C51A7", 16))
    Write-Le16 $header 4 1
    Write-Le16 $header 6 56
    Write-Le64 $header 8 $file_time
    Write-Le32 $header 16 ([uint64]$PID)
    Write-Le32 $header 20 1234
    Write-Le64 $header 24 $ticks
    Write-Le32 $header 32 9
    Write-Le64 $header 36 3
    Write-Le32 $header 44 ([Convert]::ToUInt32("282", 16))
    Write-Le32 $header 48 1
    Write-Le32 $header 52 ([Convert]::ToUInt32("01020707", 16))

    [uint64]$state = $seed
    $body = [byte[]]::new(60)
    Write-Le32 $body 0 $seed
    for ($index = 0; $index -lt $header.Length; ++$index) {
        $state = (
            [uint64]$state * 1664525 + 1013904223
        ) % 4294967296
        $body[$index + 4] =
            $header[$index] -bxor [byte](($state -shr 24) -band 0xFF)
    }

    $response = Invoke-WebRequest `
        -Method Post `
        -Uri "$server_url/event.php" `
        -Headers @{
            Authorization = "Bearer $event_token"
        } `
        -ContentType "application/octet-stream" `
        -Body $body
    Assert-Equal $response.StatusCode 200 "/event.php"

    $event_count = Invoke-PsqlScalar @"
select count(*)
from ninjaye_events
where installation_id = '$test_install_uuid'
  and event_type = 'cache.0x00000009.0x00000282';
"@
    Assert-Equal ([int]$event_count) 1 "cache event persistence"

    $artifact_bytes = [Text.Encoding]::UTF8.GetBytes("ninjaye-file-test")
    $artifact_path = Join-Path $env:TEMP `
        "ninjaye-file-test-$([Guid]::NewGuid().ToString('N')).bin"
    [IO.File]::WriteAllBytes($artifact_path, $artifact_bytes)
    $curl = (Get-Command curl.exe).Source
    $file_status = & $curl `
        --silent --show-error --output NUL --write-out "%{http_code}" `
        --request POST `
        --header "Authorization: Bearer $event_token" `
        --form "file=@$artifact_path;filename=application;type=application/octet-stream" `
        "$server_url/file.php"
    Assert-Equal $file_status "200" "/file.php"

    $artifact_sha = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($artifact_bytes)
    ).ToLowerInvariant()
    $artifact_count = Invoke-PsqlScalar @"
select count(*)
from ninjaye_artifacts
where installation_id = '$test_install_uuid'
  and sha256 = '$artifact_sha';
"@
    Assert-Equal ([int]$artifact_count) 1 "file artifact persistence"

    Write-Host "PASS: client handshake and five identities"
    Write-Host "PASS: AA challenge and server response verification"
    if (-not $SkipWin32) {
        Write-Host "PASS: Win32 handshake and challenge"
    }
    Write-Host "PASS: status2 session persistence"
    Write-Host "PASS: controlled RX region report upload"
    Write-Host "PASS: ClientInformation report contract"
    Write-Host "PASS: exact cache event endpoint"
    Write-Host "PASS: raw multipart file endpoint"
}
finally {
    if (-not $KeepTestData -and $stack_ready) {
        $null = Invoke-PsqlScalar @"
delete from ninjaye_installations
where install_id = '$test_install_id';
"@
    }
    if (-not $KeepTestData -and -not $NativeServer) {
        & docker compose `
            -p $compose_project `
            -f $compose_file `
            down --volumes --remove-orphans
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not remove the isolated integration stack."
        }
    }
    elseif (-not $KeepTestData -and $NativeServer) {
        if (
            $null -ne $native_server_process -and
            -not $native_server_process.HasExited
        ) {
            Stop-Process `
                -Id $native_server_process.Id `
                -Force `
                -ErrorAction SilentlyContinue
            $null = $native_server_process.WaitForExit(5000)
        }
    }
    elseif ($KeepTestData -and $NativeServer) {
        Write-Host "Keeping native server process: $($native_server_process.Id)"
    }
    else {
        Write-Host "Keeping integration stack project: $compose_project"
    }
    if (Get-Variable artifact_path -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $artifact_path -Force -ErrorAction SilentlyContinue
    }
    if (Get-Variable stdout -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue
    }
    if (Get-Variable stderr -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $native_environment_names) {
        $previous = $previous_native_environment[$name]
        if ($null -eq $previous) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            [Environment]::SetEnvironmentVariable($name, $previous, "Process")
        }
    }
    if ($native_server_stdout -and (Test-Path -LiteralPath $native_server_stdout)) {
        Remove-Item `
            -LiteralPath $native_server_stdout `
            -Force `
            -ErrorAction SilentlyContinue
    }
    if ($native_server_stderr -and (Test-Path -LiteralPath $native_server_stderr)) {
        Remove-Item `
            -LiteralPath $native_server_stderr `
            -Force `
            -ErrorAction SilentlyContinue
    }
    if ($null -eq $previous_server_host_port) {
        Remove-Item Env:NINJAYE_SERVER_HOST_PORT -ErrorAction SilentlyContinue
    }
    else {
        $env:NINJAYE_SERVER_HOST_PORT = $previous_server_host_port
    }
    Pop-Location
}
