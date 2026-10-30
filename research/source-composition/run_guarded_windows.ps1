param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$Arguments,
    [Parameter(Mandatory=$true)][string]$WorkingDirectory,
    [ValidateRange(0,1000)][int]$ExpectedTests = 0,
    [ValidateRange(1,120)][int]$TimeoutSeconds = 120,
    [ValidatePattern('^[a-z0-9-]{1,80}$')][string]$Prefix = 'release'
)
$ErrorActionPreference = 'Stop'
$taskDirectory = Join-Path $PSScriptRoot 'results'
New-Item -ItemType Directory -Force -Path $taskDirectory | Out-Null
$taskOutput = Join-Path $taskDirectory ($Prefix + '.stdout.txt')
$taskError = Join-Path $taskDirectory ($Prefix + '.stderr.txt')
$taskJson = Join-Path $taskDirectory ($Prefix + '-memory-result.json')
foreach ($taskPath in @($taskOutput,$taskError,$taskJson)) {
    if (Test-Path -LiteralPath $taskPath) { throw 'An attempt output already exists.' }
}
$taskRecord = [ordered]@{ accepted = $false; expected_tests = $ExpectedTests; actual_passed = $null; actual_failed = $null; actual_ignored = $null; test_counts_verified = $false; executable = $Executable; arguments = $Arguments; working_directory = $WorkingDirectory; timeout_seconds = $TimeoutSeconds }
trap {
    $taskRecord['failure'] = $_.Exception.Message
    $taskRecord['guard_exception'] = $true
    if (-not (Test-Path -LiteralPath $taskJson)) { $taskRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskJson }
    $taskRecord | ConvertTo-Json -Compress
    exit 1
}
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class KovaFoldProbeGuard {
    [StructLayout(LayoutKind.Sequential)] public struct MemoryStatus {
        public uint length, load;
        public ulong totalPhysical, availablePhysical, totalPage, availablePage;
        public ulong totalVirtual, availableVirtual, availableExtended;
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public uint length; public IntPtr descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inherit;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct StartupInfo {
        public uint cb; public string reserved, desktop, title;
        public uint x,y,xSize,ySize,xChars,yChars,fill,flags;
        public ushort show, reservedBytes; public IntPtr reservedPointer, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
        public IntPtr process, thread; public uint processId, threadId;
    }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long processTime, jobTime; public uint flags;
        public UIntPtr minimumWorking, maximumWorking;
        public uint activeProcesses; public UIntPtr affinity;
        public uint priority, scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong readOperations, writeOperations, otherOperations;
        public ulong readBytes, writeBytes, otherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
        public BasicLimits basic; public IoCounters io;
        public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessMemory {
        public uint cb, faults;
        public UIntPtr peakWorking, working, peakPaged, paged, peakNonPaged, nonPaged;
        public UIntPtr pagefile, peakPagefile, privateBytes;
    }
    public sealed class Result {
        public bool launched, hard_limit_installed, working_guard_terminated, timed_out, output_limit_exceeded;
        public ulong available_before_bytes, minimum_available_bytes, hard_process_commit_limit_bytes;
        public ulong peak_working_bytes, peak_private_commit_bytes, sampled_peak_private_bytes;
        public ulong installed_process_commit_limit_bytes, installed_job_commit_limit_bytes, peak_job_commit_bytes; public uint installed_job_flags;
        public uint process_id, exit_code;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref ExtendedLimits info,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out ExtendedLimits info,uint length,IntPtr returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfo startup,out ProcessInfo info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint sharing,ref SecurityAttributes security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint exit);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint exit);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint exit);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("psapi.dll",SetLastError=true)] static extern bool GetProcessMemoryInfo(IntPtr process,out ProcessMemory info,uint length);
    static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static bool Valid(IntPtr handle) { return handle!=IntPtr.Zero && handle!=new IntPtr(-1); }
    public static Result Run(string executable,string directory,string output,string error,string arguments,int timeoutSeconds) {
        const ulong limit=512UL*1024*1024, minimum=2UL*1024*1024*1024;
        var status=new MemoryStatus();status.length=(uint)Marshal.SizeOf<MemoryStatus>();Check(GlobalMemoryStatusEx(ref status));
        var result=new Result {available_before_bytes=status.availablePhysical,minimum_available_bytes=minimum,hard_process_commit_limit_bytes=limit};
        if(status.availablePhysical<minimum) return result;
        IntPtr job=IntPtr.Zero,stdout=IntPtr.Zero,stderr=IntPtr.Zero,stdin=IntPtr.Zero;
        ProcessInfo child=new ProcessInfo(); bool resumed=false;
        try {
            job=CreateJobObject(IntPtr.Zero,null);if(!Valid(job)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var limits=new ExtendedLimits();limits.basic.flags=0x100|0x200|0x2000;limits.processMemory=new UIntPtr(limit);limits.jobMemory=new UIntPtr(limit);
            Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf<ExtendedLimits>()));
            var security=new SecurityAttributes {length=(uint)Marshal.SizeOf<SecurityAttributes>(),inherit=true};
            stdout=CreateFile(output,0x40000000,3,ref security,1,0x80,IntPtr.Zero);
            stderr=CreateFile(error,0x40000000,3,ref security,1,0x80,IntPtr.Zero);
            stdin=CreateFile("NUL",0x80000000,3,ref security,3,0x80,IntPtr.Zero);
            if(!Valid(stdout)||!Valid(stderr)||!Valid(stdin)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var startup=new StartupInfo {cb=(uint)Marshal.SizeOf<StartupInfo>(),flags=0x100,stdin=stdin,stdout=stdout,stderr=stderr};
            var command=new StringBuilder("\""+executable+"\" "+arguments);
            Check(CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,true,0x08000004,IntPtr.Zero,directory,ref startup,out child));
            Check(AssignProcessToJobObject(job,child.process));
            ExtendedLimits installed;
            Check(QueryInformationJobObject(job,9,out installed,(uint)Marshal.SizeOf<ExtendedLimits>(),IntPtr.Zero));
            if((installed.basic.flags & 0x2300)!=0x2300 || (installed.basic.flags & 0x1800)!=0 || installed.processMemory.ToUInt64()!=limit || installed.jobMemory.ToUInt64()!=limit)
                throw new InvalidOperationException("Hard memory limit readback differs before resume");
            result.installed_process_commit_limit_bytes=installed.processMemory.ToUInt64();
            result.installed_job_commit_limit_bytes=installed.jobMemory.ToUInt64();
            result.installed_job_flags=installed.basic.flags;
            result.hard_limit_installed=true;result.process_id=child.processId;
            if(ResumeThread(child.thread)==0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
            resumed=true;result.launched=true;
            var timer=Stopwatch.StartNew();
            while(true) {
                ProcessMemory memory;
                if(GetProcessMemoryInfo(child.process,out memory,(uint)Marshal.SizeOf<ProcessMemory>())) {
                    result.peak_working_bytes=Math.Max(result.peak_working_bytes,memory.peakWorking.ToUInt64());
                    result.sampled_peak_private_bytes=Math.Max(result.sampled_peak_private_bytes,memory.privateBytes.ToUInt64());
                    if(memory.working.ToUInt64()>limit) {result.working_guard_terminated=true;Check(TerminateJobObject(job,3));}
                }
                if(timer.Elapsed.TotalSeconds>timeoutSeconds) {result.timed_out=true;Check(TerminateJobObject(job,3));}
                if(new FileInfo(output).Length>1048576 || new FileInfo(error).Length>1048576) {result.output_limit_exceeded=true;Check(TerminateJobObject(job,3));}
                uint wait=WaitForSingleObject(child.process,50);
                if(wait==0) break;
                if(wait==0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint code;Check(GetExitCodeProcess(child.process,out code));result.exit_code=code;
            ExtendedLimits actual;Check(QueryInformationJobObject(job,9,out actual,(uint)Marshal.SizeOf<ExtendedLimits>(),IntPtr.Zero));
            result.peak_private_commit_bytes=actual.peakProcessMemory.ToUInt64();
            result.peak_job_commit_bytes=actual.peakJobMemory.ToUInt64();
            ProcessMemory finalMemory;if(GetProcessMemoryInfo(child.process,out finalMemory,(uint)Marshal.SizeOf<ProcessMemory>())) result.peak_working_bytes=Math.Max(result.peak_working_bytes,finalMemory.peakWorking.ToUInt64());
            return result;
        } finally {
            if(Valid(child.process)&&!resumed) TerminateProcess(child.process,4);
            if(Valid(child.thread)) CloseHandle(child.thread);if(Valid(child.process)) CloseHandle(child.process);
            if(Valid(job)) CloseHandle(job);if(Valid(stdout)) CloseHandle(stdout);if(Valid(stderr)) CloseHandle(stderr);if(Valid(stdin)) CloseHandle(stdin);
        }
    }
}
'@
$taskResult = $null
try {
    $taskResult = [KovaFoldProbeGuard]::Run($Executable,$WorkingDirectory,$taskOutput,$taskError,$Arguments,$TimeoutSeconds)
    foreach ($taskField in $taskResult.GetType().GetFields()) { $taskRecord[$taskField.Name] = $taskField.GetValue($taskResult) }
    if (-not $taskResult.launched) { throw 'Fresh physical memory admission refused.' }
    if ($taskResult.exit_code -ne 0) { throw ('Child exit code ' + $taskResult.exit_code) }
    if (-not $taskResult.hard_limit_installed -or $taskResult.working_guard_terminated -or $taskResult.timed_out -or $taskResult.output_limit_exceeded -or $taskResult.peak_job_commit_bytes -le 0 -or $taskResult.peak_job_commit_bytes -gt 536870912) { throw 'Bounded execution control failed.' }
    if ($ExpectedTests -gt 0) {
        $taskText = Get-Content -LiteralPath $taskOutput -Raw
        $taskMatches = [regex]::Matches($taskText,'(?m)^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;')
        if ($taskMatches.Count -ne 1) { throw 'Exactly one test summary is required.' }
        $taskRecord.actual_passed = [int]$taskMatches[0].Groups[1].Value
        $taskRecord.actual_failed = [int]$taskMatches[0].Groups[2].Value
        $taskRecord.actual_ignored = [int]$taskMatches[0].Groups[3].Value
        if ($taskRecord.actual_passed -ne $ExpectedTests -or $taskRecord.actual_failed -ne 0 -or $taskRecord.actual_ignored -ne 0) { throw 'Actual test counts differ.' }
        $taskRecord.test_counts_verified = $true
    }
    $taskRecord.accepted = $true
} catch {
    $taskRecord['failure'] = $_.Exception.Message
    if ($null -eq $taskResult) { $taskRecord['launch_state_unknown_due_to_guard_exception'] = $true }
} finally {
    $taskRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskJson
}
if (Test-Path -LiteralPath $taskOutput) { Get-Content -LiteralPath $taskOutput -Tail 10 }
if (Test-Path -LiteralPath $taskError) { Get-Content -LiteralPath $taskError -Tail 10 }
$taskRecord | ConvertTo-Json -Compress
if (-not $taskRecord.accepted) { exit 1 }
exit 0
