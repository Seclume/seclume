# Runs once, as SYSTEM, at the end of the VM's unattended install (dockurr/windows calls
# C:\OEM\install.bat): the JDK, Oracle Database Free for Windows, a database user for the
# local Windows user 'seclume', and a runner that logs on as 'seclume' and does the rest.
Start-Transcript C:\OEM\setup-transcript.txt

Expand-Archive C:\OEM\jdk.zip C:\jdk-unpacked
Move-Item (Get-ChildItem C:\jdk-unpacked | Select-Object -First 1).FullName C:\jdk

Expand-Archive C:\OEM\oracle.zip C:\oracle-setup
$setup = Get-ChildItem C:\oracle-setup -Recurse -Filter setup.exe | Select-Object -First 1
$shipped = Get-ChildItem C:\oracle-setup -Recurse -Filter *.rsp | Select-Object -First 1
$password = (Get-Content -Raw C:\OEM\ora.pw).Trim()
$rsp = Join-Path $setup.DirectoryName 'seclume.rsp'
$lines = if ($shipped) { Get-Content $shipped.FullName } else { @() }
$values = @{ INSTALLDIR = 'C:\app\oracle\product\free\'; PASSWORD = $password;
             LISTENER_PORT = '1521'; EMEXPRESS_PORT = '5550'; CHAR_SET = 'AL32UTF8'; DB_DOMAIN = '' }
$out = foreach ($line in $lines) {
    $key = ($line -split '=', 2)[0].Trim()
    if ($values.ContainsKey($key)) { "$key=$($values[$key])"; $values.Remove($key) } else { $line }
}
$out += foreach ($key in $values.Keys) { "$key=$($values[$key])" }
$out | Set-Content $rsp -Encoding ascii
Write-Output "installing Oracle from $($setup.FullName)"
Start-Process $setup.FullName -Wait -ArgumentList '/s', "/v`"RSP_FILE=$rsp`"",
    "/v`"/L*v C:\OEM\oracle-install.log`"", '/v"/qn"'
Remove-Item $rsp

$sqlplus = Get-ChildItem C:\app\oracle -Recurse -Filter sqlplus.exe | Select-Object -First 1
$sqlnet = Get-ChildItem C:\app\oracle -Recurse -Filter sqlnet.ora |
    Where-Object FullName -like '*network\admin*' | Select-Object -First 1
Write-Output "sqlplus: $($sqlplus.FullName)"
Write-Output "sqlnet.ora: $($sqlnet.FullName)"
Get-Content $sqlnet.FullName

# The database user for this machine's 'seclume': os_authent_prefix, then HOST\USER.
$account = "$env:COMPUTERNAME\SECLUME".ToUpper()
$sql = @"
whenever sqlerror exit failure
alter session set container = FREEPDB1;
declare
  prefix varchar2(64);
  name varchar2(128);
begin
  select upper(value) into prefix from v`$parameter where name = 'os_authent_prefix';
  name := prefix || '$account';
  execute immediate 'create user "' || name || '" identified externally';
  execute immediate 'grant create session to "' || name || '"';
  execute immediate 'grant select on sys.v_`$session_connect_info to "' || name || '"';
  dbms_output.put_line('created ' || name);
end;
/
select name, value from v`$parameter where name in ('os_authent_prefix', 'remote_os_authent');
exit
"@
$sql | Set-Content C:\OEM\user.sql -Encoding ascii
& $sqlplus.FullName -S "sys/$password@localhost:1521/FREE as sysdba" '@C:\OEM\user.sql'
Remove-Item C:\OEM\user.sql

# A local user the database does not know, for the control.
$strangerPassword = ConvertTo-SecureString ((Get-Content -Raw C:\OEM\stranger.pw).Trim() + 'Aa1!') -AsPlainText -Force
New-LocalUser -Name stranger -Password $strangerPassword -PasswordNeverExpires | Out-Null
# The batch logon right its task needs - a test user on a test machine; Windows
# administrators are nobody special to the database.
Add-LocalGroupMember -Group Administrators -Member stranger

# The runner, as 'seclume' with its password - a real logon, so SSPI has credentials.
$action = New-ScheduledTaskAction -Execute powershell.exe `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\runner.ps1'
Register-ScheduledTask -TaskName seclume-runner -Action $action -RunLevel Highest `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "$env:COMPUTERNAME\seclume" `
    -Password (Get-Content -Raw C:\OEM\vm.pw).Trim()
Start-ScheduledTask -TaskName seclume-runner

Stop-Transcript
Copy-Item C:\OEM\setup-transcript.txt \\host.lan\Data\ -ErrorAction SilentlyContinue
