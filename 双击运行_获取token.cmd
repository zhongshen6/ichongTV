@echo off
setlocal
cd /d "%~dp0"
set "SELF_CMD=%~f0"
set "TMPPS=%TEMP%\wx96_token_scan_%RANDOM%_%RANDOM%.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$self=$env:SELF_CMD; $out=$env:TMPPS; $lines=[IO.File]::ReadAllLines($self,[Text.Encoding]::UTF8); $idx=[Array]::IndexOf($lines,'### POWERSHELL_PAYLOAD ###'); if($idx -lt 0){ throw 'payload marker not found' }; [IO.File]::WriteAllLines($out,$lines[($idx+1)..($lines.Length-1)],[Text.UTF8Encoding]::new($false))"
if errorlevel 1 (
  echo Failed to extract embedded PowerShell script.
  echo.
  echo Finished. Press any key to close.
  pause >nul
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TMPPS%"
set "EXIT_CODE=%ERRORLEVEL%"
del /f /q "%TMPPS%" >nul 2>nul
echo.
echo Finished. Press any key to close.
pause >nul
exit /b %EXIT_CODE%

### POWERSHELL_PAYLOAD ###
param(
  [string]$BaseUrl = "https://icq.cqust.edu.cn/icqust-admin",
  [string]$AppId = "wx96a1da8a627aa011",
  [string]$Platform = "wechat_mp"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
  param([string]$Message)
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
  Write-Host $line
}

function Write-Plain {
  param([string]$Message = "")
  Write-Host $Message
}

function Set-ClipboardSafe {
  param([string]$Text)

  if (-not $Text) {
    return $false
  }

  try {
    Set-Clipboard -Value $Text
    return $true
  } catch {
    try {
      Add-Type -AssemblyName System.Windows.Forms
      [Windows.Forms.Clipboard]::SetText($Text)
      return $true
    } catch {
      Write-Log "Clipboard write failed: $($_.Exception.Message)"
      return $false
    }
  }
}

function Add-MemoryScannerType {
  if ("FastMemTokenScan" -as [type]) {
    return
  }

  Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public class FastMemTokenScan {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION64 {
    public UInt64 BaseAddress;
    public UInt64 AllocationBase;
    public UInt32 AllocationProtect;
    public UInt32 __alignment1;
    public UInt64 RegionSize;
    public UInt32 State;
    public UInt32 Protect;
    public UInt32 Type;
    public UInt32 __alignment2;
  }

  static Regex Jwt = new Regex(@"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", RegexOptions.Compiled);
  static Regex Bearer = new Regex(@"Bearer\s+([A-Za-z0-9._\-~+/=]{20,2048})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
  static Regex CryptoKey = new Regex(@"\{""type""\s*:\s*""wechat_official""\s*,\s*""encryptKey""\s*:\s*""[^""\\]+""\s*,\s*""iv""\s*:\s*""[^""\\]+""\s*,\s*""version""\s*:\s*\d+\s*,\s*""expireAt""\s*:\s*\d+\s*\}", RegexOptions.Compiled);

  public static List<string> Scan(uint[] pids) {
    var found = new HashSet<string>();
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_NOACCESS = 0x01;
    const uint PAGE_GUARD = 0x100;

    foreach (var pid in pids) {
      Console.WriteLine("scan_process=" + pid);
      IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
      if (h == IntPtr.Zero) {
        Console.WriteLine("open_failed=" + pid);
        continue;
      }

      try {
        ulong addr = 0;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64));

        while (addr < 0x00007fffffffffffUL) {
          MEMORY_BASIC_INFORMATION64 mbi;
          int res = VirtualQueryEx(h, new IntPtr(unchecked((long)addr)), out mbi, (uint)mbiSize);
          if (res == 0) break;

          bool readable = mbi.State == MEM_COMMIT
            && (mbi.Protect & PAGE_NOACCESS) == 0
            && (mbi.Protect & PAGE_GUARD) == 0;

          if (readable && mbi.RegionSize > 0) {
            ulong limit = Math.Min(mbi.RegionSize, 128UL * 1024 * 1024);
            ulong off = 0;

            while (off < limit) {
              ulong chunk64 = Math.Min(2UL * 1024 * 1024, limit - off);
              byte[] buf = new byte[(int)chunk64];
              UIntPtr read;

              if (ReadProcessMemory(h, new IntPtr(unchecked((long)(mbi.BaseAddress + off))), buf, new UIntPtr(chunk64), out read)) {
                int n = (int)read.ToUInt64();
                if (n > 0) {
                  string ascii = Encoding.ASCII.GetString(buf, 0, n);
                  foreach (Match m in Jwt.Matches(ascii)) found.Add(m.Value);
                  foreach (Match m in Bearer.Matches(ascii)) found.Add(m.Groups[1].Value);
                  foreach (Match m in CryptoKey.Matches(ascii)) found.Add("KEY\t" + m.Value);
                  if (ascii.IndexOf("\\\"encryptKey\\\"", StringComparison.Ordinal) >= 0) {
                    string asciiUnescaped = ascii.Replace("\\\"", "\"");
                    foreach (Match m in CryptoKey.Matches(asciiUnescaped)) found.Add("KEY\t" + m.Value);
                  }

                  string unicode = Encoding.Unicode.GetString(buf, 0, n - (n % 2));
                  foreach (Match m in Jwt.Matches(unicode)) found.Add(m.Value);
                  foreach (Match m in Bearer.Matches(unicode)) found.Add(m.Groups[1].Value);
                  foreach (Match m in CryptoKey.Matches(unicode)) found.Add("KEY\t" + m.Value);
                  if (unicode.IndexOf("\\\"encryptKey\\\"", StringComparison.Ordinal) >= 0) {
                    string unicodeUnescaped = unicode.Replace("\\\"", "\"");
                    foreach (Match m in CryptoKey.Matches(unicodeUnescaped)) found.Add("KEY\t" + m.Value);
                  }
                }
              }

              off += chunk64;
            }
          }

          ulong next = mbi.BaseAddress + mbi.RegionSize;
          if (next <= addr) break;
          addr = next;
        }
      } finally {
        CloseHandle(h);
      }
    }

    return new List<string>(found);
  }
}
"@
}

function Get-JwtPayload {
  param([string]$Token)

  $parts = $Token -split "\."
  if ($parts.Count -lt 2) {
    return $null
  }

  $payload = $parts[1].Replace("-", "+").Replace("_", "/")
  switch ($payload.Length % 4) {
    2 { $payload += "==" }
    3 { $payload += "=" }
    1 { return $null }
  }

  try {
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return $json | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Format-TokenExpiry {
  param([string]$Token)

  $payload = Get-JwtPayload -Token $Token
  if (-not $payload -or -not $payload.exp) {
    return @{
      ExpiryText = "unknown"
      RemainingText = "unknown"
    }
  }

  $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$payload.exp).LocalDateTime
  $remaining = $expiresAt - (Get-Date)
  $remainingText = ""

  if ($remaining.TotalSeconds -le 0) {
    $remainingText = "expired"
  } else {
    $remainingText = "{0}h {1}m" -f [Math]::Floor($remaining.TotalHours), $remaining.Minutes
  }

  return @{
    ExpiryText = $expiresAt.ToString("yyyy-MM-dd HH:mm:ss")
    RemainingText = $remainingText
  }
}

function Get-Md5Hex {
  param([string]$Text)

  $md5 = [Security.Cryptography.MD5]::Create()
  try {
    return (($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object {
      $_.ToString("x2")
    }) -join "")
  } finally {
    $md5.Dispose()
  }
}

function Invoke-SignedGetNew {
  param(
    [string]$Path,
    [string]$Token,
    [string]$SignSecret,
    [object]$CryptoKeyInfo = $null
  )

  $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()
  $nonce = Get-RandomNonce
  $sign = Get-Md5Hex -Text ("GET|{0}|||{1}|{2}|{3}" -f $Path, $timestamp, $nonce, $SignSecret)

  $headers = @{
    Authorization = "Bearer $Token"
    "Content-Type" = "application/json"
    "X-Platform" = $Platform
    "X-Timestamp" = $timestamp
    "X-Sign-Version" = "2"
    "X-Nonce" = $nonce
    "X-Body-Hash" = ""
    "X-Sign" = $sign
  }

  if ($CryptoKeyInfo) {
    $headers["X-Encrypt-Type"] = [string]$CryptoKeyInfo.type
    $headers["X-Enc-Version"] = [string]$CryptoKeyInfo.version
  }

  $result = Invoke-RestMethod `
    -Uri "$BaseUrl$Path" `
    -Method GET `
    -Headers $headers `
    -TimeoutSec 15

  if ($result.encData -and $CryptoKeyInfo) {
    try {
      $plain = ConvertFrom-Wx96EncryptedData -EncData ([string]$result.encData) -CryptoKeyInfo $CryptoKeyInfo
      return $plain | ConvertFrom-Json
    } catch {
      Write-Log "Encrypted response was accepted by backend, but local course decrypt/parse failed: $($_.Exception.Message)"
      return $result
    }
  }

  return $result
}

function Get-RandomNonce {
  $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  return -join (1..8 | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
}

function ConvertFrom-Wx96EncryptedData {
  param(
    [string]$EncData,
    [object]$CryptoKeyInfo
  )

  $errors = @()
  $keyModes = @("utf8", "base64")
  if ($CryptoKeyInfo -and [int]$CryptoKeyInfo.version -ge 2) {
    $keyModes = @("base64", "utf8")
  }
  foreach ($keyMode in $keyModes) {
    try {
      $plain = ConvertFrom-Wx96EncryptedDataWithKeyMode -EncData $EncData -CryptoKeyInfo $CryptoKeyInfo -KeyMode $keyMode
      $jsonStartCandidates = @(
        $plain.IndexOf("{"),
        $plain.IndexOf("[")
      ) | Where-Object { $_ -ge 0 } | Sort-Object
      if ($jsonStartCandidates.Count -gt 0 -and $jsonStartCandidates[0] -gt 0) {
        $plain = $plain.Substring($jsonStartCandidates[0])
      }
      return $plain
    } catch {
      $errors += "$keyMode`: $($_.Exception.Message)"
    }
  }

  throw "Unable to decrypt encData. $($errors -join '; ')"
}

function ConvertFrom-Wx96EncryptedDataWithKeyMode {
  param(
    [string]$EncData,
    [object]$CryptoKeyInfo,
    [string]$KeyMode
  )

  $cipher = [Convert]::FromBase64String($EncData)
  if ($KeyMode -eq "base64") {
    $key = [Convert]::FromBase64String([string]$CryptoKeyInfo.encryptKey)
    $iv = [Convert]::FromBase64String([string]$CryptoKeyInfo.iv)
  } else {
    $key = [Text.Encoding]::UTF8.GetBytes([string]$CryptoKeyInfo.encryptKey)
    $iv = [Text.Encoding]::UTF8.GetBytes([string]$CryptoKeyInfo.iv)
  }
  if ($iv.Length -eq 12) {
    $tmp = New-Object byte[] 16
    [Array]::Copy($iv, 0, $tmp, 0, 12)
    $iv = $tmp
  }
  $aes = [Security.Cryptography.Aes]::Create()
  try {
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    return [Text.Encoding]::UTF8.GetString($plainBytes)
  } finally {
    $aes.Dispose()
  }
}

function Write-ResultSummary {
  param(
    [bool]$Usable,
    [string]$Reason = "",
    [int]$CourseCount = 0,
    [string]$Token = "",
    [string]$Credential = "",
    [object]$CryptoKeyInfo = $null
  )

  Write-Plain ""
  Write-Plain "============================================================"
  Write-Plain " Result Summary"
  Write-Plain "============================================================"
  if (-not $Usable) {
    Write-Plain "Status       : unavailable"
    if ($Reason) {
      Write-Plain "Reason       : $Reason"
    }
    Write-Plain "Token expiry : unknown"
    Write-Plain "Course count : 0"
    Write-Plain ""
    Write-Plain "Next steps   :"
    Write-Plain "  1. Keep the official mini program open in PC WeChat."
    Write-Plain "  2. Open a page that sends requests, such as course list or code sign."
    Write-Plain "  3. Run this CMD again within a few minutes."
    return
  }

  $expiry = Format-TokenExpiry -Token $Token
  Write-Plain "Status       : usable"
  Write-Plain "Course count : $CourseCount"
  Write-Plain "Token expiry : $($expiry.ExpiryText)"
  Write-Plain "Token left   : $($expiry.RemainingText)"
  if ($CryptoKeyInfo) {
    $keyExpiry = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$CryptoKeyInfo.expireAt).LocalDateTime
    $keyRemaining = $keyExpiry - (Get-Date)
    $keyRemainingText = if ($keyRemaining.TotalSeconds -le 0) {
      "expired by timestamp, but backend accepted it"
    } else {
      "{0}h {1}m" -f [Math]::Floor($keyRemaining.TotalHours), $keyRemaining.Minutes
    }
    Write-Plain "Key expiry   : $($keyExpiry.ToString("yyyy-MM-dd HH:mm:ss"))"
    Write-Plain "Key left     : $keyRemainingText"
  }

  if ($Credential) {
    $copied = Set-ClipboardSafe -Text $Credential
    Write-Plain "Clipboard    : $(if ($copied) { "Credential copied" } else { "copy failed, copy manually below" })"
    Write-Plain ""
    Write-Plain "Paste into wx96_checkin_tool.html:"
    Write-Plain "------------------------------------------------------------"
    Write-Plain $Credential
    Write-Plain "------------------------------------------------------------"
  } else {
    Write-Plain ""
    Write-Plain "Token:"
    Write-Plain "------------------------------------------------------------"
    Write-Plain $Token
    Write-Plain "------------------------------------------------------------"
  }
}

function Format-ProcessCreationTime {
  param($CreationDate)

  if (-not $CreationDate) {
    return ""
  }

  if ($CreationDate -is [datetime]) {
    return $CreationDate.ToString("yyyy-MM-dd HH:mm:ss")
  }

  return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$CreationDate)).ToString("yyyy-MM-dd HH:mm:ss")
}

function Get-RendererClientId {
  param([string]$CommandLine)

  if ($CommandLine -match "--renderer-client-id=(\d+)") {
    return [int]$Matches[1]
  }

  return -1
}

function Add-ProcessActivityInfo {
  param([object[]]$Processes)

  $pidList = @($Processes | ForEach-Object { [int]$_.ProcessId })
  $before = @{}
  Get-Process -Id $pidList -ErrorAction SilentlyContinue | ForEach-Object {
    $before[[int]$_.Id] = [double]$_.CPU
  }

  Start-Sleep -Milliseconds 800

  $after = @{}
  Get-Process -Id $pidList -ErrorAction SilentlyContinue | ForEach-Object {
    $after[[int]$_.Id] = [double]$_.CPU
  }

  foreach ($proc in $Processes) {
    $processId = [int]$proc.ProcessId
    $delta = 0.0
    if ($before.ContainsKey($processId) -and $after.ContainsKey($processId)) {
      $delta = [Math]::Max(0.0, $after[$processId] - $before[$processId])
    }

    $cmd = [string]$proc.CommandLine
    Add-Member -InputObject $proc -NotePropertyName CpuDelta -NotePropertyValue $delta -Force
    Add-Member -InputObject $proc -NotePropertyName RendererClientId -NotePropertyValue (Get-RendererClientId -CommandLine $cmd) -Force
    Add-Member -InputObject $proc -NotePropertyName IsRenderer -NotePropertyValue ($cmd -like "*--type=renderer*") -Force
    Add-Member -InputObject $proc -NotePropertyName IsPreload -NotePropertyValue ($cmd -like "*--wmpf-appid=preload*") -Force
    Add-Member -InputObject $proc -NotePropertyName IsNetworkService -NotePropertyValue ($cmd -like "*network.mojom.NetworkService*") -Force
  }
}

Write-Log "Start scanning WeChatAppEx.exe memory for $AppId token."
Write-Log "Output directory: $scriptDir"

Add-MemoryScannerType

$processes = Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq "WeChatAppEx.exe" } |
  Select-Object ProcessId, CommandLine, CreationDate

if (-not $processes) {
  Write-Log "No WeChatAppEx.exe process found. Open PC WeChat mini program first."
  exit 2
}

Add-ProcessActivityInfo -Processes @($processes)

$validToken = $null
$validCourses = $null
$validCryptoKey = $null
$allCandidates = New-Object System.Collections.Generic.HashSet[string]
$allCryptoKeys = New-Object System.Collections.Generic.HashSet[string]
$testedCredentialPairs = New-Object System.Collections.Generic.HashSet[string]
$knownTokens = @()
$knownCryptoKeyEntries = @()
$candidateIndex = 0

function Test-TokenCandidates {
  param(
    [string[]]$Tokens,
    [string]$Source,
    [object]$CryptoKeyInfo = $null,
    [string]$CryptoKeyJson = ""
  )

  foreach ($token in $Tokens) {
    [void]$allCandidates.Add($token)

    $pairKey = if ($CryptoKeyInfo -and $CryptoKeyJson) {
      "$token`t$CryptoKeyJson"
    } else {
      "$token`tNO_KEY"
    }

    if (-not $testedCredentialPairs.Add($pairKey)) {
      continue
    }

    $script:candidateIndex++
    try {
      $check = Invoke-RestMethod `
        -Uri "$BaseUrl/wechat/checkToken" `
        -Method GET `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json"; "X-Platform" = $Platform } `
        -TimeoutSec 10

      Write-Log "Candidate #$script:candidateIndex from $Source length=$($token.Length) checkToken code=$($check.code)"

      if ($check.code -ne 200 -and $check.code -ne 0) {
        continue
      }

      $signSecret = $null
      if ($check.data -and $check.data.signSecret) {
        $signSecret = [string]$check.data.signSecret
      }

      if (-not $signSecret) {
        Write-Log "Candidate #$script:candidateIndex checkToken did not return signSecret."
        continue
      }

      Write-Log "Candidate #$script:candidateIndex signSecret length=$($signSecret.Length)"

      $courses = Invoke-SignedGetNew `
        -Path "/wechat/checkIn/myCourses" `
        -Token $token `
        -SignSecret $signSecret `
        -CryptoKeyInfo $CryptoKeyInfo

      Write-Log "Candidate #$script:candidateIndex signed myCourses code=$($courses.code) msg=$($courses.msg)"

      if ($courses.code -eq 200 -or $courses.code -eq 0 -or $courses.data) {
        $script:validToken = $token
        $script:validCourses = $courses
        $script:validCryptoKey = $CryptoKeyInfo
        return $true
      }
    } catch {
      Write-Log "Candidate #$script:candidateIndex from $Source failed: $($_.Exception.Message)"
    }
  }

  return $false
}

function Add-TokenCandidate {
  param([string]$Token)

  if (-not $Token) {
    return
  }

  [void]$allCandidates.Add($Token)

  if (-not ($knownTokens -contains $Token)) {
    $script:knownTokens += $Token
  }
}

function Add-CryptoKeyCandidate {
  param(
    [string]$KeyJson,
    [int]$SourceProcessId
  )

  if (-not $KeyJson) {
    return $null
  }

  foreach ($entry in $knownCryptoKeyEntries) {
    if ($entry.Json -eq $KeyJson) {
      return $entry
    }
  }

  if ($allCryptoKeys.Add($KeyJson)) {
    try {
      $entry = [pscustomobject]@{
        Json = $KeyJson
        Info = ($KeyJson | ConvertFrom-Json)
        Pid = $SourceProcessId
      }
      $script:knownCryptoKeyEntries += $entry
      return $entry
    } catch {
      Write-Log "Ignored malformed crypto_key_info from PID=$SourceProcessId`: $($_.Exception.Message)"
    }
  }

  return $null
}

$rendererProcesses = $processes |
  Where-Object { $_.IsRenderer } |
  Sort-Object `
    @{ Expression = "CreationDate"; Descending = $true },
    @{ Expression = "RendererClientId"; Descending = $true },
    @{ Expression = "CpuDelta"; Descending = $true }

$nonRendererProcesses = $processes |
  Where-Object {
    (-not $_.IsRenderer) -and
    (-not $_.IsNetworkService)
  } |
  Sort-Object `
    @{ Expression = "CreationDate"; Descending = $true },
    @{ Expression = "CpuDelta"; Descending = $true }

$hostProcesses = $nonRendererProcesses |
  Where-Object { $_.CommandLine -notmatch "--type=" } |
  Sort-Object `
    @{ Expression = "CreationDate"; Descending = $true },
    @{ Expression = "CpuDelta"; Descending = $true }

$otherNonRendererProcesses = $nonRendererProcesses |
  Where-Object { $_.CommandLine -match "--type=" }

$networkProcesses = $processes |
  Where-Object { $_.IsNetworkService } |
  Sort-Object `
    @{ Expression = "CreationDate"; Descending = $true },
    @{ Expression = "CpuDelta"; Descending = $true }

$scanPlan = @(
  @{ Name = "main host"; Processes = @($hostProcesses) },
  @{ Name = "newest renderer"; Processes = @($rendererProcesses | Select-Object -First 3) },
  @{ Name = "remaining renderer"; Processes = @($rendererProcesses | Select-Object -Skip 3) },
  @{ Name = "network service"; Processes = @($networkProcesses) },
  @{ Name = "other WeChatAppEx"; Processes = @($otherNonRendererProcesses) }
)

Write-Log "Found $($processes.Count) WeChatAppEx.exe process(es)."
Write-Log "Scan order: main host -> newest renderer -> remaining renderer -> network service -> other."

foreach ($stage in $scanPlan) {
  $stageProcesses = @($stage.Processes)
  if ($stageProcesses.Count -eq 0) {
    continue
  }

  Write-Log "Stage '$($stage.Name)': $($stageProcesses.Count) process(es)."

  foreach ($proc in $stageProcesses) {
    $created = Format-ProcessCreationTime -CreationDate $proc.CreationDate

    Write-Log "Scanning PID=$($proc.ProcessId) created=$created cpuDelta=$('{0:N3}' -f $proc.CpuDelta) rendererClientId=$($proc.RendererClientId) preload=$($proc.IsPreload) stage=$($stage.Name)"
    $scanItems = [FastMemTokenScan]::Scan([uint32[]]@($proc.ProcessId))
    $tokens = @()
    $cryptoKeyEntries = @()

    foreach ($item in $scanItems) {
      if ($item.StartsWith("KEY`t")) {
        $keyJson = $item.Substring(4)
        $entry = Add-CryptoKeyCandidate -KeyJson $keyJson -SourceProcessId $proc.ProcessId
        if ($entry) {
          $cryptoKeyEntries += $entry
        }
      } else {
        $tokens += $item
        Add-TokenCandidate -Token $item
      }
    }

    Write-Log "PID=$($proc.ProcessId) token candidate(s)=$($tokens.Count) crypto key(s)=$($cryptoKeyEntries.Count); known token(s)=$($knownTokens.Count) known key(s)=$($knownCryptoKeyEntries.Count)"

    if ($tokens.Count -gt 0) {
      if ($knownCryptoKeyEntries.Count -gt 0) {
        foreach ($cryptoKeyEntry in $knownCryptoKeyEntries) {
          if (Test-TokenCandidates -Tokens $tokens -Source "PID=$($proc.ProcessId), keyPID=$($cryptoKeyEntry.Pid)" -CryptoKeyInfo $cryptoKeyEntry.Info -CryptoKeyJson $cryptoKeyEntry.Json) {
            break
          }
        }
      } else {
        Write-Log "PID=$($proc.ProcessId) has token candidates but no crypto_key_info; trying token verification only is not enough for the newest mini program."
      }
      if ($validToken) {
        break
      }
    }

    if ($cryptoKeyEntries.Count -gt 0 -and $knownTokens.Count -gt 0) {
      foreach ($cryptoKeyEntry in $cryptoKeyEntries) {
        if (Test-TokenCandidates -Tokens $knownTokens -Source "known token(s), keyPID=$($cryptoKeyEntry.Pid)" -CryptoKeyInfo $cryptoKeyEntry.Info -CryptoKeyJson $cryptoKeyEntry.Json) {
          break
        }
      }
      if ($validToken) {
        break
      }
    }
  }

  if ($validToken) {
    break
  }
}

Write-Log "Unique candidate count: $($allCandidates.Count)"

if ($allCandidates.Count -eq 0) {
  $reason = "No JWT/Bearer token candidate found. Make sure the official mini program is logged in and has just opened a page that sends requests."
  Write-Log $reason
  Write-ResultSummary -Usable $false -Reason $reason
  exit 3
}

if (-not $validToken) {
  if ($knownCryptoKeyEntries.Count -eq 0) {
    $reason = "Token candidate found, but crypto_key_info was not found. Open the official mini program course list or code sign page, then scan again."
  } else {
    $reason = "No valid token plus crypto_key_info pair passed backend verification."
  }
  Write-Log $reason
  Write-ResultSummary -Usable $false -Reason $reason
  exit 4
}

if (-not $validCryptoKey) {
  $reason = "Valid token found, but crypto_key_info was not found. Reopen the official mini program page and scan again."
  Write-Log $reason
  Write-ResultSummary -Usable $false -Reason $reason
  exit 5
}

$courseCount = 0
if ($validCourses.data -is [System.Array]) {
  $courseCount = $validCourses.data.Count
} elseif ($validCourses.data) {
  $courseCount = 1
}

$cryptoKeyJson = $validCryptoKey | ConvertTo-Json -Compress
$credential = "$validToken#WX96KEY#$cryptoKeyJson"

Write-ResultSummary -Usable $true -CourseCount $courseCount -Token $validToken -Credential $credential -CryptoKeyInfo $validCryptoKey
Write-Log "Done."
