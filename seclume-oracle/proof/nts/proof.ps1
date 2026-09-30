# The proof, as the local user 'seclume': an NTS login - as it comes, with encryption
# required, and with encryption off - and the control: a Windows user the database does
# not know is refused. Jars in C:\work.
$java = 'C:\jdk\bin\java.exe'
$run = '--enable-native-access=ALL-UNNAMED -cp C:\work\seclume-core.jar;C:\work\seclume-oracle.jar C:\work\NtsProof.java'
whoami
foreach ($options in '', 'nativeEncryption=required', 'nativeEncryption=off') {
    Write-Output "with '$options':"
    & cmd /c "$java $run $options 2>&1"
}

# The control runs as 'stranger', by a task with its password: a real logon of its own.
$password = (Get-Content -Raw C:\OEM\stranger.pw).Trim() + 'Aa1!'
Remove-Item C:\work\stranger.txt -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute cmd.exe -WorkingDirectory C:\work `
    -Argument "/c $java $run > C:\work\stranger.txt 2>&1"
Unregister-ScheduledTask -TaskName seclume-stranger -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName seclume-stranger -Action $action -User "$env:COMPUTERNAME\stranger" `
    -Password $password | Out-Null
Start-ScheduledTask -TaskName seclume-stranger
for ($i = 0; $i -lt 60 -and (Get-ScheduledTask -TaskName seclume-stranger).State -ne 'Ready'; $i++) {
    Start-Sleep 2
}
Start-Sleep 2
Write-Output "as stranger:"
Get-Content C:\work\stranger.txt
