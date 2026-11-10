[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo_root = Split-Path -Parent $PSScriptRoot
$config_directory = Join-Path $repo_root "config"
$private_key_path = Join-Path $config_directory "ninjaye-dev-private.pem"
$public_key_path = Join-Path $config_directory "ninjaye-dev-public.pem"
$public_header_path = Join-Path `
    $repo_root "client\dll\src\ninjaye_public_key.h"

$artifacts = @(
    $private_key_path
    $public_key_path
    $public_header_path
)

if (-not $Force -and ($artifacts | Where-Object {
            -not (Test-Path -LiteralPath $_ -PathType Leaf)
        }))
{
    $Force = $true
}

if (-not $Force)
{
    Write-Host "NinjAye development keys already exist."
    exit 0
}

$null = New-Item -ItemType Directory -Path $config_directory -Force
$null = New-Item `
    -ItemType Directory `
    -Path (Split-Path -Parent $public_header_path) `
    -Force

function Format-CppByteArray
{
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    for ($offset = 0; $offset -lt $Bytes.Length; $offset += 12)
    {
        $last = [Math]::Min($offset + 11, $Bytes.Length - 1)
        $values = for ($index = $offset; $index -le $last; ++$index)
        {
            "0x{0:X2}" -f $Bytes[$index]
        }
        $lines.Add("    " + ($values -join ", ") + ",")
    }
    return $lines -join "`n"
}

function Add-DerLength
{
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[byte]]$Destination
    )

    if ($Length -lt 0x80)
    {
        $Destination.Add([byte]$Length)
        return
    }

    $encoded = [System.Collections.Generic.List[byte]]::new()
    $remaining = $Length
    while ($remaining -gt 0)
    {
        $encoded.Insert(0, [byte]($remaining -band 0xFF))
        $remaining = $remaining -shr 8
    }
    $Destination.Add([byte](0x80 -bor $encoded.Count))
    $Destination.AddRange($encoded)
}

function ConvertTo-DerTlv
{
    param(
        [Parameter(Mandatory = $true)]
        [byte]$Tag,
        [Parameter(Mandatory = $true)]
        [byte[]]$Value
    )

    $output = [System.Collections.Generic.List[byte]]::new()
    $output.Add($Tag)
    Add-DerLength -Length $Value.Length -Destination $output
    $output.AddRange($Value)
    return ,$output.ToArray()
}

function ConvertTo-DerInteger
{
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Value
    )

    $offset = 0
    while (
        $offset -lt ($Value.Length - 1) -and
        $Value[$offset] -eq 0
    )
    {
        ++$offset
    }

    $normalized = [System.Collections.Generic.List[byte]]::new()
    if (($Value[$offset] -band 0x80) -ne 0)
    {
        $normalized.Add(0)
    }
    $normalized.AddRange(
        [byte[]]$Value[$offset..($Value.Length - 1)])
    return ConvertTo-DerTlv `
        -Tag 0x02 `
        -Value $normalized.ToArray()
}

function ConvertTo-DerSequence
{
    param(
        [Parameter(Mandatory = $true)]
        [byte[][]]$Items
    )

    $body = [System.Collections.Generic.List[byte]]::new()
    foreach ($item in $Items)
    {
        $body.AddRange([byte[]]$item)
    }
    return ConvertTo-DerTlv -Tag 0x30 -Value $body.ToArray()
}

function ConvertTo-Pem
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [byte[]]$Der
    )

    $base64 = [Convert]::ToBase64String(
        $Der,
        [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN $Label-----`n$base64`n-----END $Label-----`n"
}

if ($PSVersionTable.PSEdition -eq "Core")
{
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
}
else
{
    $rsa = New-Object `
        System.Security.Cryptography.RSACryptoServiceProvider `
        -ArgumentList 2048
    $rsa.PersistKeyInCsp = $false
}
try
{
    $parameters = $rsa.ExportParameters($false)
    $private_parameters = $rsa.ExportParameters($true)

    $private_der = ConvertTo-DerSequence -Items @(
        (ConvertTo-DerInteger -Value ([byte[]](0))),
        (ConvertTo-DerInteger -Value $private_parameters.Modulus),
        (ConvertTo-DerInteger -Value $private_parameters.Exponent),
        (ConvertTo-DerInteger -Value $private_parameters.D),
        (ConvertTo-DerInteger -Value $private_parameters.P),
        (ConvertTo-DerInteger -Value $private_parameters.Q),
        (ConvertTo-DerInteger -Value $private_parameters.DP),
        (ConvertTo-DerInteger -Value $private_parameters.DQ),
        (ConvertTo-DerInteger -Value $private_parameters.InverseQ)
    )
    $rsa_public_der = ConvertTo-DerSequence -Items @(
        (ConvertTo-DerInteger -Value $parameters.Modulus),
        (ConvertTo-DerInteger -Value $parameters.Exponent)
    )
    $algorithm_identifier = ConvertTo-DerSequence -Items @(
        [byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
            0x01, 0x01, 0x01),
        [byte[]](0x05, 0x00)
    )
    $bit_string = ConvertTo-DerTlv `
        -Tag 0x03 `
        -Value ([byte[]]((@(0) + $rsa_public_der)))
    $public_der = ConvertTo-DerSequence -Items @(
        $algorithm_identifier,
        $bit_string
    )

    $private_pem = ConvertTo-Pem -Label "RSA PRIVATE KEY" -Der $private_der
    $public_pem = ConvertTo-Pem -Label "PUBLIC KEY" -Der $public_der
    $modulus = Format-CppByteArray -Bytes $parameters.Modulus
    $exponent = Format-CppByteArray -Bytes $parameters.Exponent

    $header = @"
#ifndef NINJAYE_PUBLIC_KEY_H
#define NINJAYE_PUBLIC_KEY_H

#include <cstdint>

// Generated by scripts/generate-dev-keys.ps1. Do not commit this file.
namespace ninjaye
{
inline constexpr uint8_t k_rsa_public_exponent[] =
{
$exponent
};

inline constexpr uint8_t k_rsa_public_modulus[] =
{
$modulus
};

inline constexpr uint32_t k_rsa_public_exponent_size =
    static_cast<uint32_t>(sizeof(k_rsa_public_exponent));
inline constexpr uint32_t k_rsa_public_modulus_size =
    static_cast<uint32_t>(sizeof(k_rsa_public_modulus));
}

#endif
"@

    $utf8_without_bom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText(
        $private_key_path,
        $private_pem,
        $utf8_without_bom)
    [System.IO.File]::WriteAllText(
        $public_key_path,
        $public_pem,
        $utf8_without_bom)
    [System.IO.File]::WriteAllText(
        $public_header_path,
        $header,
        $utf8_without_bom)

    if (
        $PSVersionTable.PSEdition -eq "Core" -and
        -not $IsWindows
    )
    {
        [System.IO.File]::SetUnixFileMode(
            $private_key_path,
            [System.IO.UnixFileMode]::UserRead -bor
                [System.IO.UnixFileMode]::UserWrite)
    }
}
finally
{
    $rsa.Dispose()
}

Write-Host "Generated an RSA-2048 development key pair."
Write-Host "Private key: $private_key_path"
Write-Host "Public key:  $public_key_path"
Write-Host "C++ header:  $public_header_path"
