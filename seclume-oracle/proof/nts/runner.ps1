# Runs as the local user 'seclume' (a scheduled task with its password): the proof once,
# then whatever run.ps1 is dropped into the shared folder - how nts.sh runs it again with
# new jars without rebuilding the VM. Output goes back to the shared folder.
$share = '\\host.lan\Data'
New-Item -ItemType Directory -Force C:\work | Out-Null
Copy-Item C:\OEM\seclume-core.jar, C:\OEM\seclume-oracle.jar, C:\OEM\NtsProof.java C:\work\
& C:\OEM\proof.ps1 *> C:\work\proof.txt
Copy-Item C:\work\proof.txt $share\ -ErrorAction SilentlyContinue
while ($true) {
    if (Test-Path "$share\run.ps1") {
        Move-Item -Force "$share\run.ps1" C:\work\run.ps1
        & C:\work\run.ps1 *> C:\work\run.txt
        Copy-Item C:\work\run.txt "$share\run-$(Get-Date -Format HHmmss).txt"
    }
    Start-Sleep 10
}
