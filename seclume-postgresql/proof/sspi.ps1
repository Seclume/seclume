# A database login by Kerberos from Windows through SSPI, on a machine that is
# not in any domain - against proof/sspi-server.sh on another host. Nothing of
# it stays on this machine.
#
#   sspi.ps1 setup    -Server <host>   (as administrator) a hosts entry for the
#                                      test names, ksetup: SECLUME.TEST's KDC
#   sspi.ps1 run      -Jars <core.jar;driver.jar> -PasswordFile <alice.pw>
#                     KerberosProof twice: in a process with alice's network
#                     credentials (what runas /netonly does - the password goes
#                     to the LSA, never to the JVM), and in an ordinary one
#   sspi.ps1 teardown (as administrator) the hosts file back byte for byte,
#                     ksetup's realm, KDC and host mappings removed
#   sspi.ps1 check    what is left: nothing, or it says what
param(
    [Parameter(Mandatory)][ValidateSet('setup', 'run', 'teardown', 'check')][string]$Step,
    [string]$Server = '192.168.88.156',
    [string]$Jars,
    [string]$PasswordFile,
    [string]$Proof = (Join-Path $PSScriptRoot 'KerberosProof.java'),
    [int]$Port = 15432,
    [string]$State = "$env:ProgramData\seclume-sspi-proof"
)
$ErrorActionPreference = 'Stop'
$Realm = 'SECLUME.TEST'
$Names = 'pg.seclume.test sql.seclume.test dc.seclume.test'
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$Marker = '# seclume-sspi-proof'

switch ($Step) {
    'setup' {
        New-Item -ItemType Directory -Force $State | Out-Null
        $original = [IO.File]::ReadAllBytes($HostsFile)
        [IO.File]::WriteAllBytes("$State\hosts.orig", $original)
        $text = [Text.Encoding]::ASCII.GetString($original)
        $line = "$Server $Names $Marker`r`n"
        if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $line = "`r`n" + $line }
        [IO.File]::WriteAllBytes($HostsFile, $original + [Text.Encoding]::ASCII.GetBytes($line))
        ksetup /addkdc $Realm $Server | Out-Null
        ksetup /addhosttorealmmap .seclume.test $Realm | Out-Null
        ipconfig /flushdns | Out-Null
        "set up: $Names -> $Server, KDC for $Realm at $Server"
    }
    'run' {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NetOnly {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo {
        public int cb; public string reserved, desktop, title;
        public int x, y, xSize, ySize, xChars, yChars, fill, flags;
        public short showWindow, reserved2; public IntPtr reserved3, stdIn, stdOut, stdErr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation { public IntPtr process, thread; public int processId, threadId; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithLogonW(string user, string domain, string password,
        int logonFlags, string application, string commandLine, int creationFlags,
        IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation info);
    [DllImport("kernel32.dll")] static extern int WaitForSingleObject(IntPtr handle, int millis);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    // LOGON_NETCREDENTIALS_ONLY: the local identity stays, the network one is alice's.
    public static void Run(string user, string domain, string password, string commandLine) {
        StartupInfo startup = new StartupInfo();
        startup.cb = Marshal.SizeOf(startup);
        ProcessInformation info;
        if (!CreateProcessWithLogonW(user, domain, password, 2, null, commandLine,
                0x08000000, IntPtr.Zero, null, ref startup, out info)) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        WaitForSingleObject(info.process, 300000);
        CloseHandle(info.thread); CloseHandle(info.process);
    }
}
'@
        $java = (Get-Command java).Source
        $out = Join-Path $env:TEMP 'seclume-sspi-proof.txt'
        $command = "cmd.exe /c `"`"$java`" --enable-native-access=ALL-UNNAMED -cp `"$Jars`" `"$Proof`" $Port > `"$out`" 2>&1`""
        if (Test-Path $out) { Remove-Item $out }
        # The test user's password, read here and handed to the LSA - never to the JVM.
        $password = (Get-Content -Raw $PasswordFile).Trim()
        [NetOnly]::Run('alice', $Realm, $password, $command)
        Remove-Variable password
        '== with alice''s network credentials (runas /netonly)'
        Get-Content $out | Select-String 'PROOF'
        '== as this user, without them'
        & $java --enable-native-access=ALL-UNNAMED -cp $Jars $Proof $Port 2>&1 | Select-String 'PROOF'
        if (Test-Path $out) { Remove-Item $out }
    }
    'teardown' {
        if (Test-Path "$State\hosts.orig") {
            $original = [IO.File]::ReadAllBytes("$State\hosts.orig")
            $now = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($HostsFile))
            $kept = ($now -split "`r?`n" | Where-Object { $_ -notlike "*$Marker" })
            $was = [Text.Encoding]::ASCII.GetString($original)
            if ((($was -split "`r?`n" | Where-Object { $_ -ne '' }) -join "`n") -eq
                    (($kept | Where-Object { $_ -ne '' }) -join "`n")) {
                [IO.File]::WriteAllBytes($HostsFile, $original)      # byte for byte as it was
            } else {
                # changed meanwhile by something else: only our line goes
                [IO.File]::WriteAllText($HostsFile, (($kept -join "`r`n").TrimEnd() + "`r`n"))
            }
        }
        foreach ($name in '.seclume.test', 'sql.seclume.test') {
            ksetup /delhosttorealmmap $name $Realm 2>&1 | Out-Null
        }
        ksetup /delkdc $Realm 2>&1 | Out-Null
        foreach ($key in 'Domains', 'HostToRealm') {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\$key\$Realm"
            if (Test-Path $path) { Remove-Item -Recurse -Force $path }
        }
        ipconfig /flushdns | Out-Null
        if (Test-Path $State) { Remove-Item -Recurse -Force $State }
        'torn down'
    }
    'check' {
        $left = @()
        if (Select-String -Path $HostsFile -Pattern 'seclume' -Quiet) { $left += 'hosts file entry' }
        foreach ($key in 'Domains', 'HostToRealm') {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\$key"
            if ((Test-Path $path) -and (Get-ChildItem $path | Where-Object Name -like "*$Realm*")) {
                $left += "registry $key\$Realm"
            }
        }
        if ((ksetup | Out-String) -match $Realm) { $left += 'ksetup realm' }
        if (Test-Path $State) { $left += $State }
        if ($left.Count -eq 0) { 'nothing left' } else { 'left: ' + ($left -join ', ') }
    }
}
