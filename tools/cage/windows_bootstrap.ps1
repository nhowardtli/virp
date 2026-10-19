$ErrorActionPreference='Stop'
$root='C:\ProgramData\KestrelProvision'
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
 foreach($v in Get-Volume | Where-Object DriveLetter){
  $d=$v.DriveLetter+':'
  foreach($ver in @('2k25','2k22','w11')) {
   if(Test-Path "$d\vioserial\$ver\amd64") { & pnputil /add-driver "$d\vioserial\$ver\amd64\*.inf" /install | Out-Null; if($LASTEXITCODE -notin @(0,3010)){throw 'vioserial_driver_failed'}; break }
  }
  if(Test-Path "$d\guest-agent\qemu-ga-x86_64.msi") {
   $pi=New-Object System.Diagnostics.ProcessStartInfo
   $pi.FileName='msiexec.exe';$pi.Arguments='/i "'+$d+'\guest-agent\qemu-ga-x86_64.msi" /qn /norestart';$pi.UseShellExecute=$false
   $p=New-Object System.Diagnostics.Process;$p.StartInfo=$pi;[void]$p.Start();$p.WaitForExit()
   if($p.ExitCode -notin @(0,3010)){throw 'guest_agent_install_failed'}
  }
 }
 $a=Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
 Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -Dhcp Disabled
 New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress 10.0.50.233 -PrefixLength 24 -DefaultGateway 10.0.50.1 | Out-Null
 Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses 1.1.1.1
 Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
 Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0
 Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1
 New-NetFirewallRule -DisplayName 'Kestrel scoped management RDP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.10.0/24 -Profile Any | Out-Null
 Set-Service TermService -StartupType Automatic; Start-Service TermService
 Set-Service QEMU-GA -StartupType Automatic; Start-Service QEMU-GA
 $result=@{success=$true;hostname=$env:COMPUTERNAME;recipe='windows2025-v2'}
} catch {$result=@{success=$false;error=[string]$_.Exception.Message;hostname=$env:COMPUTERNAME}}
finally {
 $wl='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
 Set-ItemProperty $wl AutoAdminLogon '0'
 Remove-ItemProperty $wl DefaultPassword -ErrorAction SilentlyContinue
 Remove-ItemProperty $wl AutoLogonCount -ErrorAction SilentlyContinue
 Remove-Item C:\Windows\Panther\unattend.xml,C:\Windows\Panther\Unattend\unattend.xml,C:\Windows\System32\Sysprep\unattend.xml -Force -ErrorAction SilentlyContinue
}
$result|ConvertTo-Json -Compress|Set-Content -Encoding UTF8 "$root\bootstrap.json"
