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
  [string]$AppId = "wx96a1da8a627aa011"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
  param([string]$Message)
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
  Write-Host $line
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

                  string unicode = Encoding.Unicode.GetString(buf, 0, n - (n % 2));
                  foreach (Match m in Jwt.Matches(unicode)) found.Add(m.Value);
                  foreach (Match m in Bearer.Matches(unicode)) found.Add(m.Groups[1].Value);
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

function Write-ResultSummary {
  param(
    [bool]$Usable,
    [string]$Reason = "",
    [int]$CourseCount = 0,
    [string]$Token = ""
  )

  Write-Log "----- Result Summary -----"
  if (-not $Usable) {
    Write-Log "Status: unavailable"
    if ($Reason) {
      Write-Log "Reason: $Reason"
    }
    Write-Log "Token expiry: unknown"
    Write-Log "Course count: 0"
    return
  }

  $expiry = Format-TokenExpiry -Token $Token
  Write-Log "Status: usable"
  Write-Log "Token: $Token"
  Write-Log "Token expiry: $($expiry.ExpiryText)"
  Write-Log "Token remaining: $($expiry.RemainingText)"
  Write-Log "Course count: $CourseCount"
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
$allCandidates = New-Object System.Collections.Generic.HashSet[string]
$candidateIndex = 0

function Test-TokenCandidates {
  param(
    [string[]]$Tokens,
    [string]$Source
  )

  foreach ($token in $Tokens) {
    if (-not $allCandidates.Add($token)) {
      continue
    }

    $script:candidateIndex++
    try {
      $check = Invoke-RestMethod `
        -Uri "$BaseUrl/wechat/checkToken" `
        -Method GET `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
        -TimeoutSec 10

      Write-Log "Candidate #$script:candidateIndex from $Source length=$($token.Length) checkToken code=$($check.code)"

      if ($check.code -ne 200 -and $check.code -ne 0) {
        continue
      }

      $courses = Invoke-RestMethod `
        -Uri "$BaseUrl/wechat/checkIn/myCourses" `
        -Method GET `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
        -TimeoutSec 15

      Write-Log "Candidate #$script:candidateIndex myCourses code=$($courses.code) msg=$($courses.msg)"

      if ($courses.code -eq 200 -or $courses.code -eq 0 -or $courses.data) {
        $script:validToken = $token
        $script:validCourses = $courses
        return $true
      }
    } catch {
      Write-Log "Candidate #$script:candidateIndex from $Source failed: $($_.Exception.Message)"
    }
  }

  return $false
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

$networkProcesses = $processes |
  Where-Object { $_.IsNetworkService } |
  Sort-Object `
    @{ Expression = "CreationDate"; Descending = $true },
    @{ Expression = "CpuDelta"; Descending = $true }

$scanPlan = @(
  @{ Name = "newest renderer"; Processes = @($rendererProcesses | Select-Object -First 3) },
  @{ Name = "remaining renderer"; Processes = @($rendererProcesses | Select-Object -Skip 3) },
  @{ Name = "network service"; Processes = @($networkProcesses) },
  @{ Name = "other WeChatAppEx"; Processes = @($nonRendererProcesses) }
)

Write-Log "Found $($processes.Count) WeChatAppEx.exe process(es)."
Write-Log "Scan order: newest renderer -> remaining renderer -> network service -> other."

foreach ($stage in $scanPlan) {
  $stageProcesses = @($stage.Processes)
  if ($stageProcesses.Count -eq 0) {
    continue
  }

  Write-Log "Stage '$($stage.Name)': $($stageProcesses.Count) process(es)."

  foreach ($proc in $stageProcesses) {
    $created = Format-ProcessCreationTime -CreationDate $proc.CreationDate

    Write-Log "Scanning PID=$($proc.ProcessId) created=$created cpuDelta=$('{0:N3}' -f $proc.CpuDelta) rendererClientId=$($proc.RendererClientId) preload=$($proc.IsPreload) stage=$($stage.Name)"
    $tokens = [FastMemTokenScan]::Scan([uint32[]]@($proc.ProcessId))
    Write-Log "PID=$($proc.ProcessId) candidate(s) found=$($tokens.Count)"

    if ($tokens.Count -gt 0 -and (Test-TokenCandidates -Tokens $tokens -Source "PID=$($proc.ProcessId)")) {
      break
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
  $reason = "No valid token passed backend verification."
  Write-Log $reason
  Write-ResultSummary -Usable $false -Reason $reason
  exit 4
}

$courseCount = 0
if ($validCourses.data -is [System.Array]) {
  $courseCount = $validCourses.data.Count
} elseif ($validCourses.data) {
  $courseCount = 1
}

Write-ResultSummary -Usable $true -CourseCount $courseCount -Token $validToken
Write-Log "Done."
