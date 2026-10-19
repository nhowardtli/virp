$ErrorActionPreference='Stop'
$r=@{success=$false}
try {
 $os=Get-CimInstance Win32_OperatingSystem
 $cs=Get-CimInstance Win32_ComputerSystemProduct
 $mp=Get-MpComputerStatus
 $wl=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
 $tpm=Get-Tpm
 $r=@{success=$true;hostname=[string]$env:COMPUTERNAME;os=[string]$os.Caption;version=[string]$os.Version;boot=[string]$os.LastBootUpTime.ToUniversalTime().ToString('o');uuid=[string]$cs.UUID;secure_boot=[bool](Confirm-SecureBootUEFI);tpm_present=[bool]$tpm.TpmPresent;tpm_ready=[bool]$tpm.TpmReady;defender=[bool]$mp.RealTimeProtectionEnabled;firewalls=@(Get-NetFirewallProfile|ForEach-Object{[bool]$_.Enabled});ips=@(Get-NetIPAddress -AddressFamily IPv4|ForEach-Object{[string]$_.IPAddress});autologon_disabled=([string]$wl.AutoAdminLogon -ne '1');autologon_secret_absent=($null -eq $wl.DefaultPassword);answer_files_absent=(!(Test-Path C:\Windows\Panther\unattend.xml) -and !(Test-Path C:\Windows\Panther\Unattend\unattend.xml));rdp_running=((Get-Service TermService).Status -eq 'Running');agent_running=((Get-Service QEMU-GA).Status -eq 'Running')}
} catch {$r=@{success=$false;error=[string]$_.Exception.Message}}
$r|ConvertTo-Json -Depth 3 -Compress|Set-Content -Encoding UTF8 'C:\ProgramData\KestrelProvision\VERIFY_FILE'
