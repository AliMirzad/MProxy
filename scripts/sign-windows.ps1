# Authenticode-signs the native helper of a staged Windows runtime package.
#
# Called by scripts/package.mjs when PRIVATE_PROXY_SIGN_THUMBPRINT is set. The certificate (a code
# signing certificate from a public CA, or from the company's internal CA whose root is deployed to
# the machines by Group Policy) must be in Cert:\CurrentUser\My or Cert:\LocalMachine\My.
#
#   powershell -File scripts/sign-windows.ps1 -File <path to private-proxy-host.exe> -Thumbprint <SHA1>
#       [-TimestampServer http://timestamp.digicert.com]
#
# Xray is NOT re-signed: it ships byte-for-byte as the official release so that its pinned SHA-256
# stays valid (an Authenticode signature is embedded in the file and would change the hash).
param(
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [string]$TimestampServer = ""
)
$ErrorActionPreference = "Stop"
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
    Where-Object { $_.Thumbprint -eq $Thumbprint.Replace(" ", "").ToUpper() } | Select-Object -First 1
if (-not $cert) { throw "Code signing certificate $Thumbprint not found (must have a private key and the Code Signing usage)." }
$params = @{ FilePath = $File; Certificate = $cert; HashAlgorithm = "SHA256" }
if ($TimestampServer) { $params.TimestampServer = $TimestampServer }
$sig = Set-AuthenticodeSignature @params
if ($sig.Status -ne "Valid") { throw "Signing failed: $($sig.Status) $($sig.StatusMessage)" }
Write-Host "signed $File ($($cert.Subject))"
