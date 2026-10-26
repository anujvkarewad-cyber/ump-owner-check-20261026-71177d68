param(
    [string]$ExpectedSha256 = 'd1fa7225118741fa6a6817825c1d9b09d6910eafba84edee93e371b6ec00048c',
    [string[]]$SearchRoots = @(),
    [string]$ReportPath = (Join-Path $HOME 'gpg-packet-diagnose.txt')
)

$ErrorActionPreference = 'Continue'
function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)
    $Message | Tee-Object -FilePath $ReportPath -Append | Out-Null
}

[System.IO.File]::WriteAllText($ReportPath, "GPG_READ_ONLY_DIAGNOSTIC_START`r`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Log "timestamp_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Log "powershell_version=$($PSVersionTable.PSVersion.ToString())"
Write-Log "mode=READ_ONLY_NO_PASSPHRASE_NO_DECRYPTION_NO_RESTORE"

$gpgCmd = Get-Command gpg.exe -ErrorAction SilentlyContinue
if (-not $gpgCmd) {
    Write-Log 'STATUS=STOP_GPG_NOT_FOUND'
    Write-Log 'DIAGNOSTIC_DONE_NO_DECRYPTION'
    exit 2
}
$gpg = $gpgCmd.Source
Write-Log "gpg_path_leaf=$(Split-Path $gpg -Leaf)"
$gpgVer = & $gpg --version 2>&1 | Select-Object -First 2
Write-Log "gpg_version=$(($gpgVer | ForEach-Object { $_.ToString() }) -join ' ')"

$gpgconfCmd = Get-Command gpgconf.exe -ErrorAction SilentlyContinue
if ($gpgconfCmd) {
    $homeDir = & $gpgconfCmd.Source --list-dirs homedir 2>$null
    Write-Log "gpg_homedir=$(if ($homeDir) { ($homeDir | ForEach-Object { $_.ToString() }) -join ' ' } else { 'unknown' })"
}
$agentCmd = Get-Command gpg-connect-agent.exe -ErrorAction SilentlyContinue
if ($agentCmd) {
    $agentOut = & $agentCmd.Source 'getinfo version' /bye 2>&1 | Select-Object -First 3
    Write-Log "agent_version=$(($agentOut | ForEach-Object { $_.ToString() }) -join ' ')"
}
$procs = @(Get-Process gpg-agent -ErrorAction SilentlyContinue)
Write-Log ("agent_processes=" + (($procs | ForEach-Object { "$($_.Id):$($_.ProcessName)" }) -join ';'))

$gnupgHome = if ($env:GNUPGHOME) { $env:GNUPGHOME } else { Join-Path $env:APPDATA 'gnupg' }
$confFiles = @(
    (Join-Path $gnupgHome 'gpg.conf'),
    (Join-Path $gnupgHome 'gpg-agent.conf'),
    (Join-Path $HOME '.gnupg\gpg.conf'),
    (Join-Path $HOME '.gnupg\gpg-agent.conf')
) | Where-Object { $_ } | Select-Object -Unique
Write-Log 'gpg_conf_selected_lines:'
foreach ($c in $confFiles) {
    if (Test-Path -LiteralPath $c) {
        $leaf = Split-Path $c -Leaf
        Get-Content -LiteralPath $c | Where-Object { $_ -match 'pinentry-mode|no-symkey-cache|use-agent|cipher-algo|s2k' } | ForEach-Object { Write-Log "conf[$leaf]=$_" }
    }
}

if ($SearchRoots.Count -eq 0) {
    $defaultRoots = @(
        (Join-Path $HOME 'Downloads'),
        (Join-Path $HOME 'Desktop'),
        (Join-Path $HOME 'Documents'),
        (Join-Path $HOME 'ump-recovery'),
        (Join-Path $HOME 'ump-recovery-test'),
        'D:\UMP-Recovery'
    )
    $SearchRoots = @($defaultRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($SearchRoots.Count -eq 0) { $SearchRoots = @($HOME) }
}
Write-Log "search_roots_count=$($SearchRoots.Count)"

$gpgFiles = @()
foreach ($root in $SearchRoots) {
    $gpgFiles += @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter *.gpg -ErrorAction SilentlyContinue)
}
Write-Log "gpg_files_scanned=$($gpgFiles.Count)"

$archive = $null
foreach ($f in $gpgFiles) {
    try {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -eq $ExpectedSha256.ToLowerInvariant()) { $archive = $f; break }
    } catch { }
}

if (-not $archive) {
    Write-Log 'STATUS=STOP_EXACT_HASH_ARCHIVE_NOT_FOUND'
    Write-Log "expected_sha256=$ExpectedSha256"
    Write-Log 'DIAGNOSTIC_DONE_NO_DECRYPTION'
    exit 2
}

$safeArchive = $archive.FullName.Replace($HOME, '~')
Write-Log "archive_path=$safeArchive"
Write-Log "archive_bytes=$($archive.Length)"
Write-Log "archive_sha256=$((Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
Write-Log 'packet_summary_with_list_only:'

$packetRaw = & $gpg --batch --no-tty --list-only --list-packets $archive.FullName 2>&1
$packetLines = @($packetRaw | ForEach-Object { $_.ToString() })
$filtered = @($packetLines | Where-Object { $_ -match 'gpg:|symkey enc packet|encrypted data packet|aead|cipher|s2k|hash|mdc_method|tag 20|AEAD|version' } | ForEach-Object { if ($_ -match '^\s*salt\b') { '    salt [omitted]' } else { $_ } } | Select-Object -First 40)
foreach ($line in $filtered) { Write-Log $line }

$safeReport = $ReportPath.Replace($HOME, '~')
Write-Log 'STATUS=DIAGNOSTIC_DONE_NO_DECRYPTION'
Write-Log "report=$safeReport"
Write-Log 'share_only_this_sanitized_report;_never_share_archive_or_passphrase'
exit 0
