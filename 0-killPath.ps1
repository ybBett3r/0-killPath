#Requires -Version 7.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NEXUS Task Sentinel — Game-Optimized Process Authority Engine
.DESCRIPTION
    Real-time task manager featuring:
      • SeDebugPrivilege escalation via AdjustTokenPrivileges (touches protected processes)
      • Native Win32 P/Invoke for priority, affinity, working-set, and termination
      • JSON-driven game-mode profiles (regex pattern → priority class)
      • Explorer.exe kill/restore for headless gaming sessions
      • Streamlined regex + threshold filtering
      • Distilled 8-tier severity colorization
      • Persistent rolling log + state snapshot for full restore
.PARAMETER Mode
    Apply named profile from profiles.json (e.g. MaxFPS, Streaming, Workstation)
.PARAMETER Headless
    Apply Mode and exit — no interactive UI
.PARAMETER FilterPattern
    Regex applied to process name for visible set (default: '.*')
.PARAMETER MinCPU
    Hide processes whose cumulative CPU seconds fall below this threshold
.PARAMETER RefreshMs
    UI refresh interval in milliseconds (default: 1000)
.PARAMETER Limit
    Maximum process rows to render (default: 25)
.PARAMETER NoExplorerKill
    Hard safety lock against explorer.exe termination
.PARAMETER InstallRoot
    Override config/log root (default: %LOCALAPPDATA%\NexusTaskSentinel)
.EXAMPLE
    .\NexusTaskSentinel.ps1 -Mode MaxFPS
.EXAMPLE
    .\NexusTaskSentinel.ps1 -Mode Streaming -Headless
.EXAMPLE
    .\NexusTaskSentinel.ps1 -FilterPattern '^(chrome|discord)' -MinCPU 5
#>
[CmdletBinding()]
param(
    [string]$Mode,
    [switch]$Headless,
    [string]$FilterPattern = '.*',
    [double]$MinCPU        = 0,
    [int]$RefreshMs        = 1000,
    [int]$Limit            = 25,
    [switch]$NoExplorerKill,
    [string]$InstallRoot   = "$env:LOCALAPPDATA\NexusTaskSentinel"
)

#region ========================== Globals ==========================
$ErrorActionPreference   = 'Stop'
$Script:Running          = $true
$Script:SortColumn       = 'CPU'
$Script:SortDescending   = $true
$Script:PriorityHistory  = @{}    # PID → original priority class for restore
$Script:ExplorerKilled   = $false
$Script:Profiles         = @{}
$Script:CurrentMode      = if ($Mode) { $Mode } else { '<none>' }
$Script:LogPath          = Join-Path $InstallRoot "logs\sentinel_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { [Console]::CursorVisible = $false } catch {}

$logDir = Split-Path $Script:LogPath
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
#endregion

#region ====================== Telemetry ======================
function Write-Telemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('TRACE','INFO','OK','WARN','ERR','CRIT','STEP','GAME')]
        [string]$Level = 'INFO',
        [switch]$NoConsole
    )
    $ts   = (Get-Date).ToString('HH:mm:ss.fff')
    $line = "[$ts][$Level] $Message"

    try { Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($NoConsole) { return }

    $palette = @{
        'TRACE' = @{ FG='DarkGray';  BG=$null      }
        'INFO'  = @{ FG='Gray';      BG=$null      }
        'OK'    = @{ FG='Green';     BG=$null      }
        'WARN'  = @{ FG='Yellow';    BG=$null      }
        'ERR'   = @{ FG='Red';       BG=$null      }
        'CRIT'  = @{ FG='White';     BG='DarkRed'  }
        'STEP'  = @{ FG='Cyan';      BG=$null      }
        'GAME'  = @{ FG='Magenta';   BG=$null      }
    }
    $p = $palette[$Level]
    if ($p.BG) { Write-Host $line -ForegroundColor $p.FG -BackgroundColor $p.BG }
    else       { Write-Host $line -ForegroundColor $p.FG }
}
#endregion

#region ================== Native Authority Layer ==================
$Script:NativeSrc = @'
using System;
using System.Runtime.InteropServices;

public static class NexusNative
{
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    public const uint TOKEN_ADJUST_PRIVILEGES   = 0x0020;
    public const uint TOKEN_QUERY               = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED      = 0x0002;
    public const uint PROCESS_SET_INFORMATION   = 0x0200;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED     = 0x1000;
    public const uint PROCESS_TERMINATE         = 0x0001;
    public const uint PROCESS_SET_QUOTA         = 0x0100;

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr h, uint da, out IntPtr tk);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr tk, bool dis, ref TOKEN_PRIVILEGES np, uint len, IntPtr op, IntPtr opl);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint da, bool inh, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetPriorityClass(IntPtr h, uint pc);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetPriorityClass(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr h, uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetProcessAffinityMask(IntPtr h, IntPtr mask);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EmptyWorkingSet(IntPtr h);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    public static int LastError() { return Marshal.GetLastWin32Error(); }

    public static bool EnableSeDebug() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) return false;
        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) {
            CloseHandle(token); return false;
        }
        var tp = new TOKEN_PRIVILEGES {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES[] {
                new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            }
        };
        bool r = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        CloseHandle(token);
        return r && err == 0;
    }

    public static bool ForceSetPriority(uint pid, uint pc) {
        IntPtr h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED, false, pid);
        if (h == IntPtr.Zero) return false;
        bool r = SetPriorityClass(h, pc);
        CloseHandle(h);
        return r;
    }

    public static uint GetPriority(uint pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (h == IntPtr.Zero) return 0;
        uint pc = GetPriorityClass(h);
        CloseHandle(h);
        return pc;
    }

    public static bool ForceTerminate(uint pid) {
        IntPtr h = OpenProcess(PROCESS_TERMINATE, false, pid);
        if (h == IntPtr.Zero) return false;
        bool r = TerminateProcess(h, 1);
        CloseHandle(h);
        return r;
    }

    public static bool SetAffinity(uint pid, ulong mask) {
        IntPtr h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED, false, pid);
        if (h == IntPtr.Zero) return false;
        bool r = SetProcessAffinityMask(h, (IntPtr)mask);
        CloseHandle(h);
        return r;
    }

    public static bool TrimWorkingSet(uint pid) {
        IntPtr h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED, false, pid);
        if (h == IntPtr.Zero) return false;
        bool r = EmptyWorkingSet(h);
        CloseHandle(h);
        return r;
    }
}
'@

$Script:PriorityClassMap = [ordered]@{
    'Idle'        = 0x00000040
    'BelowNormal' = 0x00004000
    'Normal'      = 0x00000020
    'AboveNormal' = 0x00008000
    'High'        = 0x00000080
    'Realtime'    = 0x00000100
}
$Script:PriorityClassReverse = @{}
foreach ($k in $Script:PriorityClassMap.Keys) {
    $Script:PriorityClassReverse[[int]$Script:PriorityClassMap[$k]] = $k
}

function Initialize-NexusAuthority {
    try {
        if (-not ('NexusNative' -as [type])) {
            Write-Telemetry "Compiling native interop layer..." STEP
            Add-Type -TypeDefinition $Script:NativeSrc -Language CSharp -ErrorAction Stop
        }
        Write-Telemetry "Enabling SeDebugPrivilege on current token..." STEP
        if ([NexusNative]::EnableSeDebug()) {
            Write-Telemetry "SeDebugPrivilege ENABLED — extended process authority active" OK
            return $true
        } else {
            $err = [NexusNative]::LastError()
            Write-Telemetry "SeDebug enable failed (Win32 err $err) — operating in limited authority mode" WARN
            return $false
        }
    } catch {
        Write-Telemetry "Authority init failure: $($_.Exception.Message)" ERR
        return $false
    }
}
#endregion

#region ================== Process Operations ==================
function Set-NexusPriority {
    param(
        [Parameter(Mandatory)][uint32]$ProcessId,
        [Parameter(Mandatory)][string]$Priority
    )
    try {
        if (-not $Script:PriorityClassMap.Contains($Priority)) {
            Write-Telemetry "Unknown priority class: $Priority" ERR
            return $false
        }
        if (-not $Script:PriorityHistory.ContainsKey($ProcessId)) {
            $current = [NexusNative]::GetPriority($ProcessId)
            if ($current -gt 0 -and $Script:PriorityClassReverse.ContainsKey([int]$current)) {
                $Script:PriorityHistory[$ProcessId] = $Script:PriorityClassReverse[[int]$current]
            }
        }
        $r = [NexusNative]::ForceSetPriority($ProcessId, [uint32]$Script:PriorityClassMap[$Priority])
        if ($r) { Write-Telemetry "PRIO  PID $ProcessId → $Priority" OK -NoConsole }
        else    { Write-Telemetry "PRIO  PID $ProcessId failed (protected/access denied)" WARN -NoConsole }
        return $r
    } catch {
        Write-Telemetry "Priority error PID $ProcessId : $($_.Exception.Message)" ERR
        return $false
    }
}

function Stop-NexusProcess {
    param(
        [Parameter(Mandatory)][uint32]$ProcessId,
        [string]$Name = ''
    )
    try {
        $r = [NexusNative]::ForceTerminate($ProcessId)
        if ($r) {
            Write-Telemetry "TERM  $Name (PID $ProcessId)" OK
            return $true
        }
        # Managed fallback
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Telemetry "TERM  $Name (PID $ProcessId) [managed fallback]" OK
        return $true
    } catch {
        Write-Telemetry "TERM  $Name (PID $ProcessId) FAILED — $($_.Exception.Message)" ERR
        return $false
    }
}

function Set-NexusAffinity {
    param([uint32]$ProcessId, [uint64]$Mask)
    try {
        $r = [NexusNative]::SetAffinity($ProcessId, $Mask)
        if ($r) { Write-Telemetry ("AFF   PID {0} → 0x{1:X}" -f $ProcessId,$Mask) OK }
        else    { Write-Telemetry "AFF   PID $ProcessId FAILED" WARN }
        return $r
    } catch { Write-Telemetry "Affinity error: $_" ERR; return $false }
}

function Compress-NexusWorkingSet {
    param([uint32]$ProcessId)
    try { return [NexusNative]::TrimWorkingSet($ProcessId) }
    catch { return $false }
}

# ------------------------------------------------------------------
# Resolve-NexusTargets
#   Unified multi-mode selector. Accepts:
#     Index/range : '1,2,3'   '1-25'   '1,3;5-10'   '1-3,5,7-9'
#     Name query  : 'svch'    'chrome'  (substring, case-insensitive)
#   Auto-detects mode by character class. Deduplicates by PID.
#   Index mode resolves against $Procs (visible set).
#   Name mode resolves against full Get-Process table.
# ------------------------------------------------------------------
function Resolve-NexusTargets {
    param(
        [Parameter(Mandatory)][string]$Spec,
        [Parameter(Mandatory)][array]$Procs
    )
    $resolved = [System.Collections.Generic.List[object]]::new()
    $seen     = [System.Collections.Generic.HashSet[int]]::new()

    if ($Spec -match '^[\d,\-;\s]+$') {
        # ---- Index / range mode ----
        $tokens = $Spec -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($tok in $tokens) {
            if ($tok -match '^(\d+)\s*-\s*(\d+)$') {
                $a = [int]$Matches[1]; $b = [int]$Matches[2]
                if ($a -gt $b) { $a, $b = $b, $a }
                for ($i = $a; $i -le $b; $i++) {
                    if ($i -ge 1 -and $i -le $Procs.Count) {
                        $p = $Procs[$i - 1]
                        if ($seen.Add([int]$p.PID)) { $resolved.Add($p) }
                    }
                }
            } elseif ($tok -match '^\d+$') {
                $i = [int]$tok
                if ($i -ge 1 -and $i -le $Procs.Count) {
                    $p = $Procs[$i - 1]
                    if ($seen.Add([int]$p.PID)) { $resolved.Add($p) }
                }
            }
        }
        Write-Telemetry "Resolver: index/range mode → $($resolved.Count) target(s)" TRACE -NoConsole
    }
    else {
        # ---- Name substring mode (full process table) ----
        $all = Get-Process -ErrorAction SilentlyContinue
        $matched = $all | Where-Object { $_.ProcessName -like "*$Spec*" }
        foreach ($m in $matched) {
            if ($m.Id -eq $PID) { continue }   # never select self
            if ($seen.Add([int]$m.Id)) {
                $resolved.Add([PSCustomObject]@{
                    PID  = $m.Id
                    Name = $m.ProcessName
                })
            }
        }
        Write-Telemetry "Resolver: name mode '$Spec' → $($resolved.Count) target(s)" TRACE -NoConsole
    }

    # NOTE: do NOT use `return ,$resolved.ToArray()` here.
    # The caller wraps this call in @(...), so the unary comma would
    # double-wrap the array — yielding a 1-element nested array and
    # causing `[uint32]$t.PID` casts downstream to throw on Object[].
    return $resolved.ToArray()
}
#endregion

#region ====================== Explorer Control ======================
function Stop-NexusExplorer {
    if ($NoExplorerKill) {
        Write-Telemetry "Explorer kill blocked by -NoExplorerKill safety lock" WARN
        return
    }
    try {
        Write-Telemetry "Terminating explorer.exe shell..." STEP
        $instances = @(Get-Process -Name explorer -ErrorAction SilentlyContinue)
        foreach ($e in $instances) {
            [NexusNative]::ForceTerminate([uint32]$e.Id) | Out-Null
        }
        $Script:ExplorerKilled = $true
        Write-Telemetry "Explorer terminated ($($instances.Count) instance(s))" OK
    } catch { Write-Telemetry "Explorer kill error: $_" ERR }
}

function Start-NexusExplorer {
    try {
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Write-Telemetry "Restoring explorer.exe shell..." STEP
            Start-Process -FilePath "$env:WINDIR\explorer.exe"
            Start-Sleep -Milliseconds 600
        }
        $Script:ExplorerKilled = $false
        Write-Telemetry "Explorer shell restored" OK
    } catch { Write-Telemetry "Explorer restore error: $_" ERR }
}
#endregion

#region ===================== Profile Engine =====================
function Import-NexusProfiles {
    $path = Join-Path $InstallRoot 'profiles\profiles.json'
    if (-not (Test-Path $path)) {
        Write-Telemetry "profiles.json missing at $path — bootstrap not run?" WARN
        return
    }
    try {
        $obj = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
        $Script:Profiles = $obj
        Write-Telemetry "Loaded $($obj.Keys.Count) profile(s): $($obj.Keys -join ', ')" OK
    } catch { Write-Telemetry "Profile load failure: $($_.Exception.Message)" ERR }
}

function Invoke-NexusProfile {
    param([Parameter(Mandatory)][string]$Name)
    if (-not $Script:Profiles.ContainsKey($Name)) {
        Write-Telemetry "Profile '$Name' not in registry" ERR
        return
    }
    $p = $Script:Profiles[$Name]
    Write-Telemetry "═══ APPLYING PROFILE: $Name ═══" GAME
    Write-Telemetry "Description: $($p.Description)" INFO
    $Script:CurrentMode = $Name

    if ($p.KillExplorer) { Stop-NexusExplorer }

    $allProc  = @(Get-Process -ErrorAction SilentlyContinue)
    $demoted  = 0
    $elevated = 0

    foreach ($rule in @($p.ProcessRules)) {
        $matches = $allProc | Where-Object { $_.ProcessName -match $rule.Pattern }
        foreach ($t in $matches) {
            if (Set-NexusPriority -ProcessId ([uint32]$t.Id) -Priority $rule.Priority) { $demoted++ }
        }
    }
    foreach ($rule in @($p.ElevateRules)) {
        $matches = $allProc | Where-Object { $_.ProcessName -match $rule.Pattern }
        foreach ($t in $matches) {
            if (Set-NexusPriority -ProcessId ([uint32]$t.Id) -Priority $rule.Priority) { $elevated++ }
        }
    }

    if ($p.TrimWorkingSets) {
        Write-Telemetry "Trimming working sets across all accessible processes..." STEP
        $trimmed = 0
        foreach ($t in $allProc) {
            if (Compress-NexusWorkingSet -ProcessId ([uint32]$t.Id)) { $trimmed++ }
        }
        Write-Telemetry "Working sets trimmed: $trimmed processes" OK
    }

    Write-Telemetry "Profile '$Name' applied — demoted: $demoted | elevated: $elevated" GAME
}

function Restore-NexusState {
    Write-Telemetry "═══ RESTORING SNAPSHOT ═══" STEP
    $restored = 0
    foreach ($pidKey in @($Script:PriorityHistory.Keys)) {
        if (Set-NexusPriority -ProcessId ([uint32]$pidKey) -Priority $Script:PriorityHistory[$pidKey]) {
            $restored++
        }
    }
    if ($Script:ExplorerKilled) { Start-NexusExplorer }
    $Script:PriorityHistory.Clear()
    $Script:CurrentMode = '<restored>'
    Write-Telemetry "Snapshot restored — $restored priorities reverted" OK
}
#endregion

#region ===================== System Telemetry =====================
function Get-SystemTelemetry {
    try {
        $cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
                Measure-Object -Property LoadPercentage -Average).Average
        $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
        $freeMB  = [math]::Round($os.FreePhysicalMemory / 1024, 0)
        $usedMB  = $totalMB - $freeMB
        $usedPct = if ($totalMB -gt 0) { [math]::Round(($usedMB / $totalMB) * 100, 1) } else { 0 }
        [PSCustomObject]@{
            CPUPct     = [math]::Round(($cpu ?? 0), 1)
            MemPct     = $usedPct
            MemUsedMB  = $usedMB
            MemTotalMB = $totalMB
            ProcCount  = (Get-Process -ErrorAction SilentlyContinue).Count
            Uptime     = (New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).ToString('d\.hh\:mm\:ss')
        }
    } catch {
        [PSCustomObject]@{ CPUPct=0; MemPct=0; MemUsedMB=0; MemTotalMB=0; ProcCount=0; Uptime='?' }
    }
}
#endregion

#region ====================== UI Renderer ======================
function Get-NexusProcessView {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.ProcessName -notmatch $FilterPattern) { return }
            $cpu = [math]::Round(($_.CPU ?? 0), 2)
            if ($cpu -lt $MinCPU) { return }
            $pri = try { $_.PriorityClass.ToString() } catch { 'N/A' }
            [PSCustomObject]@{
                PID      = $_.Id
                Name     = $_.ProcessName
                CPU      = $cpu
                MEM      = [math]::Round($_.WorkingSet64 / 1MB, 1)
                PMem     = $_.WorkingSet64
                Priority = $pri
                Threads  = $_.Threads.Count
                Handles  = $_.HandleCount
            }
        } catch {}
    } |
    Sort-Object -Property $Script:SortColumn -Descending:$Script:SortDescending |
    Select-Object -First $Limit
}

function Show-NexusDashboard {
    param([array]$Procs, $Tel)

    Clear-Host
    $bar = '═' * 112

    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host " NEXUS TASK SENTINEL " -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
    Write-Host (" Authority: Admin+SeDebug │ Mode: {0} │ Filter: {1} │ MinCPU: {2}" -f `
        $Script:CurrentMode, $FilterPattern, $MinCPU) -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor DarkCyan

    # Telemetry strip
    $cpuCol = if ($Tel.CPUPct -gt 80) { 'Red' } elseif ($Tel.CPUPct -gt 50) { 'Yellow' } else { 'Green' }
    $memCol = if ($Tel.MemPct -gt 80) { 'Red' } elseif ($Tel.MemPct -gt 60) { 'Yellow' } else { 'Green' }
    Write-Host ' CPU: ' -NoNewline -ForegroundColor Gray
    Write-Host ("{0,5:N1}%" -f $Tel.CPUPct) -NoNewline -ForegroundColor $cpuCol
    Write-Host '  │  RAM: ' -NoNewline -ForegroundColor Gray
    Write-Host ("{0,5:N1}% ({1}/{2} MB)" -f $Tel.MemPct,$Tel.MemUsedMB,$Tel.MemTotalMB) -NoNewline -ForegroundColor $memCol
    Write-Host '  │  Procs: ' -NoNewline -ForegroundColor Gray
    Write-Host $Tel.ProcCount -NoNewline -ForegroundColor Cyan
    Write-Host '  │  Uptime: ' -NoNewline -ForegroundColor Gray
    Write-Host $Tel.Uptime -NoNewline -ForegroundColor Cyan
    Write-Host '  │  Explorer: ' -NoNewline -ForegroundColor Gray
    Write-Host $(if ($Script:ExplorerKilled) {'KILLED'} else {'running'}) `
        -ForegroundColor $(if ($Script:ExplorerKilled) {'Magenta'} else {'Green'})

    Write-Host ('─' * 112) -ForegroundColor DarkGray
    Write-Host (" {0,-3} {1,-7} {2,-8} {3,-10} {4,-13} {5,-5} {6,-7} {7}" -f `
        '#','PID','CPU%','MEM(MB)','Priority','Thr','Hnd','Process') -ForegroundColor White
    Write-Host ('─' * 112) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $Procs.Count; $i++) {
        $p = $Procs[$i]
        $col = switch ($true) {
            ($p.CPU -gt 50)              { 'Red';      break }
            ($p.CPU -gt 25)              { 'Yellow';   break }
            ($p.Priority -eq 'RealTime') { 'Magenta';  break }
            ($p.Priority -eq 'High')     { 'Green';    break }
            ($p.Priority -eq 'Idle')     { 'DarkCyan'; break }
            ($p.MEM -gt 1000)            { 'Cyan';     break }
            default                      { 'Gray' }
        }
        Write-Host (" {0,-3} {1,-7} {2,-8:N1} {3,-10:N1} {4,-13} {5,-5} {6,-7} {7}" -f `
            ($i+1), $p.PID, $p.CPU, $p.MEM, $p.Priority, $p.Threads, $p.Handles, $p.Name) `
            -ForegroundColor $col
    }

    Write-Host ('─' * 112) -ForegroundColor DarkGray
    Write-Host ' [#] Kill │ K Kill-Pattern │ P Priority(multi) │ A Affinity │ T Trim(multi) │ E Explorer │ G Profile │ R Restore │ S Sort │ F Filter │ D Dir │ Q Quit' `
        -ForegroundColor DarkGray
    Write-Host (' Sort: {0} {1}' -f $Script:SortColumn, $(if($Script:SortDescending){'▼'}else{'▲'})) `
        -ForegroundColor DarkGray
}
#endregion

#region ====================== Input Handler ======================
function Read-NexusInput {
    param([string]$Prompt)
    try { [Console]::CursorVisible = $true } catch {}
    Write-Host ''
    Write-Host " > $Prompt : " -NoNewline -ForegroundColor Cyan
    $r = Read-Host
    try { [Console]::CursorVisible = $false } catch {}
    return $r
}

function Invoke-NexusKey {
    param([ConsoleKeyInfo]$Key, [array]$Procs)

    switch ($Key.Key) {
        'Q' { $Script:Running = $false }

        'R' { Restore-NexusState }

        'S' {
            $cols = 'CPU','PMem','Handles','Threads','Name'
            $idx  = ($cols.IndexOf($Script:SortColumn) + 1) % $cols.Count
            $Script:SortColumn = $cols[$idx]
        }

        'D' { $Script:SortDescending = -not $Script:SortDescending }

        'F' {
            $f = Read-NexusInput "Filter regex (current: $FilterPattern)"
            if ($f) { Set-Variable -Name FilterPattern -Value $f -Scope Script }
        }

        'E' {
            if ($Script:ExplorerKilled) { Start-NexusExplorer } else { Stop-NexusExplorer }
            Start-Sleep -Milliseconds 400
        }

        'G' {
            $names = $Script:Profiles.Keys -join ', '
            $n = Read-NexusInput "Profile [$names]"
            if ($n -and $Script:Profiles.ContainsKey($n)) {
                Invoke-NexusProfile -Name $n
                Start-Sleep -Milliseconds 600
            }
        }

        'T' {
            $spec = Read-NexusInput "Trim WS — indices/range/name (e.g. '1-10'  '1,3,5'  'chrome')"
            if (-not $spec) { return }
            $targets = @(Resolve-NexusTargets -Spec $spec -Procs $Procs)
            if ($targets.Count -eq 0) {
                Write-Telemetry "No targets matched: '$spec'" WARN
                Start-Sleep -Milliseconds 600
                return
            }
            $ok = 0
            foreach ($t in $targets) {
                if ($t -isnot [psobject] -or -not $t.PSObject.Properties['PID']) {
                    Write-Telemetry "Type guard tripped: skipping non-target $($t.GetType().Name)" WARN
                    continue
                }
                if (Compress-NexusWorkingSet -ProcessId ([uint32]$t.PID)) { $ok++ }
            }
            Write-Telemetry ("BATCH TRIM: {0} / {1} working sets compressed" -f $ok, $targets.Count) OK
            Start-Sleep -Milliseconds 600
        }

        'A' {
            $idx = Read-NexusInput "Affinity for index #"
            if ($idx -match '^\d+$' -and [int]$idx -ge 1 -and [int]$idx -le $Procs.Count) {
                $mask = Read-NexusInput "Hex mask (e.g. FF = cores 0-7, F0 = cores 4-7)"
                try {
                    $m = [Convert]::ToUInt64($mask, 16)
                    Set-NexusAffinity -ProcessId ([uint32]$Procs[[int]$idx - 1].PID) -Mask $m | Out-Null
                    Start-Sleep -Milliseconds 400
                } catch { Write-Telemetry "Bad mask: $_" ERR; Start-Sleep -Milliseconds 600 }
            }
        }

        'K' {
            $pat = Read-NexusInput "Kill pattern (regex applied to ProcessName)"
            if ($pat) {
                $kills = @(Get-Process -ErrorAction SilentlyContinue |
                          Where-Object ProcessName -Match $pat |
                          Where-Object { $_.Id -ne $PID })   # never kill self
                Write-Telemetry "Match count: $($kills.Count)" INFO
                foreach ($k in $kills) {
                    Stop-NexusProcess -ProcessId ([uint32]$k.Id) -Name $k.ProcessName | Out-Null
                }
                Start-Sleep -Milliseconds 600
            }
        }

        'P' {
            $spec = Read-NexusInput "Targets — indices/range/name (e.g. '1,2,3'  '1-25'  '1,3;5-10'  'svch')"
            if (-not $spec) { return }

            $targets = @(Resolve-NexusTargets -Spec $spec -Procs $Procs)
            if ($targets.Count -eq 0) {
                Write-Telemetry "No targets matched: '$spec'" WARN
                Start-Sleep -Milliseconds 800
                return
            }

            Write-Telemetry "Resolved $($targets.Count) target(s):" STEP
            $preview = $targets | Select-Object -First 8
            foreach ($t in $preview) {
                Write-Telemetry ("  -> {0,-30} (PID {1})" -f $t.Name, $t.PID) INFO
            }
            if ($targets.Count -gt 8) {
                Write-Telemetry "  ... and $($targets.Count - 8) more" INFO
            }

            Write-Host '  1=Idle  2=BelowNormal  3=Normal  4=AboveNormal  5=High  6=Realtime  0=Cancel' -ForegroundColor DarkGray
            $c = Read-NexusInput "Priority class for $($targets.Count) target(s)"
            $map = @{'1'='Idle';'2'='BelowNormal';'3'='Normal';'4'='AboveNormal';'5'='High';'6'='Realtime'}
            if (-not $map.ContainsKey($c)) {
                Write-Telemetry "Aborted (cancel/invalid)" WARN
                Start-Sleep -Milliseconds 600
                return
            }

            # Safety gate: confirm Realtime escalation OR large batches
            if ($map[$c] -eq 'Realtime' -or $targets.Count -gt 15) {
                $conf = Read-NexusInput "CONFIRM '$($map[$c])' on $($targets.Count) process(es)? (y/N)"
                if ($conf -notmatch '^[yY]$') {
                    Write-Telemetry "Aborted by user" WARN
                    Start-Sleep -Milliseconds 600
                    return
                }
            }

            $ok = 0; $fail = 0
            foreach ($t in $targets) {
                if ($t -isnot [psobject] -or -not $t.PSObject.Properties['PID']) {
                    Write-Telemetry "Type guard tripped: skipping non-target $($t.GetType().Name)" WARN
                    $fail++; continue
                }
                if (Set-NexusPriority -ProcessId ([uint32]$t.PID) -Priority $map[$c]) { $ok++ }
                else { $fail++ }
            }
            Write-Telemetry ("BATCH PRIO -> {0}: {1} ok / {2} failed across {3} target(s)" -f `
                $map[$c], $ok, $fail, $targets.Count) GAME
            Start-Sleep -Milliseconds 800
        }

        default {
            if ($Key.KeyChar -match '\d') {
                $i = [int]::Parse($Key.KeyChar.ToString()) - 1
                if ($i -ge 0 -and $i -lt $Procs.Count) {
                    $t = $Procs[$i]
                    if ($t.PID -ne $PID) {
                        Stop-NexusProcess -ProcessId ([uint32]$t.PID) -Name $t.Name | Out-Null
                        Start-Sleep -Milliseconds 200
                    }
                }
            }
        }
    }
}
#endregion

#region ========================== Main ==========================
try {
    Write-Telemetry "═══════════ NEXUS TASK SENTINEL STARTING ═══════════" STEP
    Write-Telemetry "Log: $Script:LogPath" INFO
    Write-Telemetry "PID: $PID │ User: $env:USERNAME │ Host: $env:COMPUTERNAME" INFO

    Initialize-NexusAuthority | Out-Null
    Import-NexusProfiles

    if ($Mode) { Invoke-NexusProfile -Name $Mode }

    if ($Headless) {
        Write-Telemetry "Headless run complete — exiting" OK
        return
    }

    Write-Telemetry "Entering interactive loop (Q to quit)" STEP
    Start-Sleep -Milliseconds 700

    while ($Script:Running) {
        $procs = @(Get-NexusProcessView)
        $tel   = Get-SystemTelemetry
        Show-NexusDashboard -Procs $procs -Tel $tel

        $waited = 0
        while ($waited -lt $RefreshMs -and $Script:Running) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                Invoke-NexusKey -Key $key -Procs $procs
                break
            }
            Start-Sleep -Milliseconds 50
            $waited += 50
        }
    }
}
catch {
    Write-Telemetry "FATAL: $($_.Exception.Message)" CRIT
    Write-Telemetry $_.ScriptStackTrace ERR
}
finally {
    try { [Console]::CursorVisible = $true } catch {}
    Clear-Host
    Write-Telemetry "═══════════ NEXUS SENTINEL SHUTDOWN ═══════════" STEP

    if ($Script:PriorityHistory.Count -gt 0 -or $Script:ExplorerKilled) {
        try {
            $resp = Read-Host "`nRestore original priorities and explorer? (Y/n)"
            if ($resp -ne 'n' -and $resp -ne 'N') { Restore-NexusState }
        } catch {}
    }
    Write-Telemetry "Log saved → $Script:LogPath" OK
}
#endregion
