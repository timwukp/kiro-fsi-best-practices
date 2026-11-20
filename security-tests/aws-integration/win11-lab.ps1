<#
win11-lab.ps1 - builds and drives a Windows 11 lab on a DISPOSABLE EC2 host (as SYSTEM, via SSM).

  $env:W11_PHASE = 'host'; powershell -NoProfile -ExecutionPolicy Bypass -File win11-lab.ps1 -RepoDir C:\kiro-test\repo

Started by run-integration.sh stage "win11:<phase>" on the lab host that stage "win11host" launched:
an m8i instance with nested virtualization, Windows Server 2025. Never part of "all".

The lab: Hyper-V on the host, an internal switch with NAT (192.168.250.0/24), one Generation 2 VM
"win11" with a virtual TPM and Secure Boot, built from the Windows 11 Enterprise Evaluation ISO that
Microsoft publishes (x64, en-US), checked against Microsoft's published SHA-256. Local accounts:
labadmin (Administrators) and devuser (Users, signed in automatically, so a desktop session exists).
Their passwords are SSM SecureStrings /kiro-fsi-test/win11-guest-admin and /kiro-fsi-test/win11-guest-user;
the host's own administrator (for Fleet Manager Remote Desktop) is /kiro-fsi-test/win11-host-admin.
None of them is ever printed.

Phases (run in this order; each can be run again):
  host    local administrator for Fleet Manager; the Hyper-V role (exit code 3010: SSM restarts the
          host and runs the phase again)
  iso     download the evaluation ISO from Microsoft and check its SHA-256
  vm      the switch and NAT, the VHDX, the VM, first boot, guest network, a checkpoint "clean"
  status  what exists now
  kit-baseline, kit-install, kit-policy
          the W2 kit in the VM as labadmin through PowerShell Direct (clean-device check; signature
          and silent install of the system-wide Kiro IDE; policy, Intune wrappers and tamper test)
  wk      phase WK (windows-kiro-cli-suite.ps1) inside the VM as SYSTEM, through a one-time scheduled
          task. The guest has no AWS access: the host reads /kiro-fsi-test/kiro-api-key and hands it
          in as a file that only SYSTEM and Administrators can read; the suite deletes it as soon as
          it has read it. W11_WK_VCREDIST=1 first installs Microsoft's Visual C++ 2015-2022
          Redistributable x64 (signature checked), which Kiro CLI 3.5.0 needs and a clean Windows 11
          does not have; W11_WK_RECHECK=1 adds the suite's re-check block (section 9b).

Output: "CHECK <id> PASS|FAIL|SKIP|INFO <detail>" lines and "PHASE W11-<phase> RESULT pass= fail= skip= info=".
#>
param([Parameter(Mandatory = $true)][string]$RepoDir)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Phase = "$env:W11_PHASE"
$Region = "$env:W11_REGION"
if (-not $Region) { $Region = 'ap-southeast-1' }
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0; $script:Info = 0
$script:Secrets = New-Object System.Collections.Generic.List[string]

function Protect-Line([string]$Text) {
  $t = [string]$Text
  foreach ($s in $script:Secrets) { if ($s) { $t = $t.Replace($s, '<secret>') } }
  if ($env:COMPUTERNAME -and $env:COMPUTERNAME.Length -ge 3) { $t = [regex]::Replace($t, [regex]::Escape($env:COMPUTERNAME), '<host>', 'IgnoreCase') }
  $t = [regex]::Replace($t, '(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])', '<12-digits>')
  $t = [regex]::Replace($t, '[^\x20-\x7e]', '?')
  return $t
}
function Out-Line([string]$Text) { [Console]::Out.WriteLine((Protect-Line $Text)) }
function Check([string]$Id, [string]$Status, [string]$Detail = '') {
  Out-Line ("CHECK $Id $Status " + ($Detail -replace '[\r\n]+', ' '))
  switch ($Status) { 'PASS' { $script:Pass++ } 'FAIL' { $script:Fail++ } 'INFO' { $script:Info++ } default { $script:Skip++ } }
}
function Finish {
  Out-Line "PHASE W11-$Phase RESULT pass=$script:Pass fail=$script:Fail skip=$script:Skip info=$script:Info"
  if ($script:Fail -ne 0) { exit 1 } else { exit 0 }
}
function Get-Secret([string]$Name) {
  $v = ''
  try { $v = [string](Get-SSMParameter -Name "/kiro-fsi-test/$Name" -WithDecryption $true -Region $Region -ErrorAction Stop).Value } catch { }
  if ($v) { $script:Secrets.Add($v) }
  return $v
}
function New-Cred([string]$User, [string]$Password) {
  return (New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force)))
}

$Lab = 'C:\win11lab'
$IsoUrl = 'https://go.microsoft.com/fwlink/?LinkId=2382600&clcid=0x409&culture=en-us&country=us'
# Microsoft: "How to verify the authenticity of a Windows 11, version 26H2 Evaluation ISO file",
# Enterprise Eval x64 EN-US (read 2026-11-19).
$IsoSha256 = 'bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38'
$Iso = Join-Path $Lab 'win11-enterprise-eval-26h2-x64-en-us.iso'
$VmName = 'win11'
$Vhd = Join-Path $Lab 'win11.vhdx'
$SwitchName = 'LabNAT'
$NatPrefix = '192.168.250.0/24'
$HostIp = '192.168.250.1'
$GuestIp = '192.168.250.10'
$GuestName = 'W11-LAB'

Out-Line "NOTE W11 lab, phase '$Phase', on $((Get-CimInstance Win32_OperatingSystem).Caption) as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace '^.*\\','')"
New-Item -ItemType Directory -Force -Path $Lab | Out-Null

switch ($Phase) {

# ------------------------------------------------------------------------------------------------
'host' {
  $pw = Get-Secret 'win11-host-admin'
  if (-not $pw) { Check 'W11.host-admin' 'FAIL' 'no /kiro-fsi-test/win11-host-admin parameter (run-integration.sh win11host creates it)'; Finish }
  try {
    $u = Get-LocalUser -Name 'labadmin' -ErrorAction SilentlyContinue
    if ($u) { Set-LocalUser -Name 'labadmin' -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop }
    else { New-LocalUser -Name 'labadmin' -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires -Description 'Kiro Windows 11 lab (Fleet Manager)' -ErrorAction Stop | Out-Null }
    $admins = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    try { Add-LocalGroupMember -Group $admins -Member 'labadmin' -ErrorAction Stop } catch { if ("$($_.Exception.Message)" -notmatch '(?i)already') { throw } }
    Check 'W11.host-admin' 'PASS' 'local administrator labadmin on the host (password: SSM /kiro-fsi-test/win11-host-admin), for Fleet Manager Remote Desktop'
  } catch { Check 'W11.host-admin' 'FAIL' $_.Exception.Message }

  # The user-data shutdown timer does not survive a restart; a one-time scheduled task does.
  $deadline = 0
  if ([long]::TryParse("$env:W11_DEADLINE", [ref]$deadline) -and $deadline -gt 0) {
    $at = [DateTimeOffset]::FromUnixTimeSeconds($deadline).LocalDateTime
    try {
      $act = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\shutdown.exe') -Argument '/s /f /t 0 /c "kiro-fsi-test failsafe" /d p:0:0'
      Register-ScheduledTask -TaskName 'KiroLabFailsafe' -Action $act -Trigger (New-ScheduledTaskTrigger -Once -At $at) -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
      Check 'W11.failsafe' 'PASS' "scheduled task KiroLabFailsafe powers the host off (and so terminates it) at $($at.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
    } catch { Check 'W11.failsafe' 'FAIL' $_.Exception.Message }
  } else { Check 'W11.failsafe' 'INFO' 'no W11_DEADLINE given: only the user-data timer of the first start applies' }

  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  Check 'W11.cpu' 'INFO' "$($cpu.Name.Trim()); cores=$($cpu.NumberOfCores); logical=$($cpu.NumberOfLogicalProcessors); VMMonitorModeExtensions=$($cpu.VMMonitorModeExtensions); VirtualizationFirmwareEnabled=$($cpu.VirtualizationFirmwareEnabled); SecondLevelAddressTranslation=$($cpu.SecondLevelAddressTranslationExtensions)"
  $f = Get-WindowsFeature -Name Hyper-V
  if (-not $f.Installed) {
    $r = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -ErrorAction SilentlyContinue
    if (-not $r -or -not $r.Success) { Check 'W11.hyperv' 'FAIL' "Install-WindowsFeature Hyper-V failed: exit=$($r.ExitCode). Is nested virtualization enabled for this instance?"; Finish }
    Out-Line "NOTE Hyper-V installed (restart needed: $($r.RestartNeeded)); restarting the host, SSM runs this phase again"
    exit 3010
  }
  $cs = Get-CimInstance Win32_ComputerSystem
  if ($cs.HypervisorPresent) {
    $vh = Get-VMHost -ErrorAction SilentlyContinue
    Check 'W11.hyperv' 'PASS' "Hyper-V role installed and the hypervisor is running on the host (nested virtualization); logical processors for VMs=$($vh.LogicalProcessorCount); memory=$([int]($cs.TotalPhysicalMemory / 1GB)) GiB"
  } else { Check 'W11.hyperv' 'FAIL' 'Hyper-V is installed but the hypervisor is not running (HypervisorPresent=False)' }
  Finish
}

# ------------------------------------------------------------------------------------------------
'iso' {
  $have = ''
  if (Test-Path -LiteralPath $Iso -PathType Leaf) { $have = (Get-FileHash -Algorithm SHA256 -LiteralPath $Iso).Hash.ToLowerInvariant() }
  if ($have -ne $IsoSha256) {
    Remove-Item -LiteralPath $Iso, "$Iso.part" -Force -ErrorAction SilentlyContinue
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & curl.exe -s -S -L --fail --retry 3 --max-time 3600 -o "$Iso.part" $IsoUrl 2>&1 | ForEach-Object { Out-Line "NOTE curl: $_" }
    $sw.Stop()
    if ((Test-Path -LiteralPath "$Iso.part") -and $LASTEXITCODE -eq 0) { Move-Item -LiteralPath "$Iso.part" -Destination $Iso -Force }
    if (-not (Test-Path -LiteralPath $Iso)) { Check 'W11.iso-download' 'FAIL' "download failed (curl exit=$LASTEXITCODE) from $IsoUrl"; Finish }
    Check 'W11.iso-download' 'INFO' "bytes=$((Get-Item -LiteralPath $Iso).Length); seconds=$([int]$sw.Elapsed.TotalSeconds); from $IsoUrl"
    $have = (Get-FileHash -Algorithm SHA256 -LiteralPath $Iso).Hash.ToLowerInvariant()
  }
  if ($have -eq $IsoSha256) { Check 'W11.iso-sha256' 'PASS' "sha256 equals the value Microsoft publishes for Windows 11 Enterprise 26H2 Evaluation x64 en-US ($IsoSha256)" }
  else { Check 'W11.iso-sha256' 'FAIL' "sha256 is $have, Microsoft publishes $IsoSha256; the file was removed"; Remove-Item -LiteralPath $Iso -Force -ErrorAction SilentlyContinue }
  Finish
}

# ------------------------------------------------------------------------------------------------
'vm' {
  Import-Module Hyper-V -ErrorAction SilentlyContinue
  if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) { Check 'W11.vm' 'FAIL' 'the Hyper-V module is not available: run phase host first'; Finish }
  if (-not (Test-Path -LiteralPath $Iso -PathType Leaf)) { Check 'W11.vm' 'FAIL' 'no verified ISO: run phase iso first'; Finish }
  $admPw = Get-Secret 'win11-guest-admin'; $usrPw = Get-Secret 'win11-guest-user'
  if (-not $admPw -or -not $usrPw) { Check 'W11.vm' 'FAIL' 'the guest password parameters are missing (run-integration.sh win11host creates them)'; Finish }
  $adm = New-Cred '.\labadmin' $admPw

  # Network: internal switch, host address, NAT.
  try {
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) { New-VMSwitch -Name $SwitchName -SwitchType Internal -ErrorAction Stop | Out-Null }
    $ifx = (Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -eq "vEthernet ($SwitchName)" }).ifIndex
    if (-not (Get-NetIPAddress -IPAddress $HostIp -ErrorAction SilentlyContinue)) { New-NetIPAddress -IPAddress $HostIp -PrefixLength 24 -InterfaceIndex $ifx -ErrorAction Stop | Out-Null }
    if (-not (Get-NetNat -Name $SwitchName -ErrorAction SilentlyContinue)) { New-NetNat -Name $SwitchName -InternalIPInterfaceAddressPrefix $NatPrefix -ErrorAction Stop | Out-Null }
    Check 'W11.network' 'PASS' "internal switch $SwitchName, host $HostIp/24, NAT $NatPrefix"
  } catch { Check 'W11.network' 'FAIL' $_.Exception.Message; Finish }
  $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notlike 'vEthernet*' -and $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object -First 1 | ForEach-Object { $_.ServerAddresses })

  if (-not (Get-VM -Name $VmName -ErrorAction SilentlyContinue)) {
    $mounted = $null; $vhdMounted = $false
    try {
      $mounted = Mount-DiskImage -ImagePath $Iso -PassThru -ErrorAction Stop
      $isoL = ($mounted | Get-Volume).DriveLetter
      $wim = "${isoL}:\sources\install.wim"
      if (-not (Test-Path -LiteralPath $wim)) { $wim = "${isoL}:\sources\install.esd" }
      $img = @(Get-WindowsImage -ImagePath $wim -ErrorAction Stop | Where-Object { $_.ImageName -like '*Enterprise*' })[0]
      if (-not $img) { throw "no Enterprise image in $wim" }
      Check 'W11.image' 'INFO' "$($img.ImageName) (index $($img.ImageIndex)) from $(Split-Path -Leaf $wim)"
      Remove-Item -LiteralPath $Vhd -Force -ErrorAction SilentlyContinue
      New-VHD -Path $Vhd -SizeBytes 100GB -Dynamic -ErrorAction Stop | Out-Null
      $disk = Mount-VHD -Path $Vhd -Passthru -ErrorAction Stop | Get-Disk
      $vhdMounted = $true
      Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop
      $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter -ErrorAction Stop
      Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'System' -Force -Confirm:$false -ErrorAction Stop | Out-Null
      New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction Stop | Out-Null
      $os = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -AssignDriveLetter -ErrorAction Stop
      Format-Volume -Partition $os -FileSystem NTFS -NewFileSystemLabel 'Windows' -Force -Confirm:$false -ErrorAction Stop | Out-Null
      $efiL = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber).DriveLetter
      $osL = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $os.PartitionNumber).DriveLetter
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      Expand-WindowsImage -ImagePath $wim -Index $img.ImageIndex -ApplyPath "${osL}:\" -ErrorAction Stop | Out-Null
      $sw.Stop()
      $bcd = & bcdboot.exe "${osL}:\Windows" /s "${efiL}:" /f UEFI 2>&1
      if ($LASTEXITCODE -ne 0) { throw "bcdboot failed: $bcd" }
      # Unattended first start: local accounts, no Microsoft account screens, devuser signed in automatically.
      $x = [System.Security.SecurityElement]
      $unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>$GuestName</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>labadmin</Name><Group>Administrators</Group><DisplayName>Lab administrator</DisplayName>
            <Password><Value>$($x::Escape($admPw))</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
          <LocalAccount wcm:action="add">
            <Name>devuser</Name><Group>Users</Group><DisplayName>Developer (standard user)</DisplayName>
            <Password><Value>$($x::Escape($usrPw))</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled><Username>devuser</Username><LogonCount>9999999</LogonCount>
        <Password><Value>$($x::Escape($usrPw))</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"@
      New-Item -ItemType Directory -Force -Path "${osL}:\Windows\Panther" | Out-Null
      [System.IO.File]::WriteAllText("${osL}:\Windows\Panther\unattend.xml", $unattend, (New-Object System.Text.UTF8Encoding($false)))
      Check 'W11.vhdx' 'PASS' "image applied in $([int]$sw.Elapsed.TotalSeconds) s; UEFI boot files written; unattend.xml placed (local accounts labadmin and devuser, automatic sign-in of devuser)"
    } catch {
      Check 'W11.vhdx' 'FAIL' $_.Exception.Message
      if ($vhdMounted) { Dismount-VHD -Path $Vhd -ErrorAction SilentlyContinue }
      if ($mounted) { Dismount-DiskImage -ImagePath $Iso -ErrorAction SilentlyContinue | Out-Null }
      Finish
    }
    Dismount-VHD -Path $Vhd -ErrorAction SilentlyContinue
    Dismount-DiskImage -ImagePath $Iso -ErrorAction SilentlyContinue | Out-Null
    try {
      New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 12GB -VHDPath $Vhd -SwitchName $SwitchName -ErrorAction Stop | Out-Null
      Set-VM -Name $VmName -ProcessorCount 4 -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStopAction ShutDown -ErrorAction Stop
      Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows' -ErrorAction Stop
      Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector -ErrorAction Stop
      Enable-VMTPM -VMName $VmName -ErrorAction Stop
      Enable-VMIntegrationService -VMName $VmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
      Start-VM -Name $VmName -ErrorAction Stop
      Check 'W11.vm-created' 'PASS' "Generation 2 VM ${VmName}: 4 vCPU, 12 GiB, Secure Boot (MicrosoftWindows template), virtual TPM, switch $SwitchName; started"
    } catch { Check 'W11.vm-created' 'FAIL' $_.Exception.Message; Finish }
  } else {
    if ((Get-VM -Name $VmName).State -ne 'Running') { Start-VM -Name $VmName -ErrorAction SilentlyContinue }
    Check 'W11.vm-created' 'INFO' "VM $VmName exists already (state: $((Get-VM -Name $VmName).State))"
  }

  # First start: specialize and OOBE run unattended. Wait for PowerShell Direct.
  $sw = [System.Diagnostics.Stopwatch]::StartNew(); $up = $false; $lastErr = ''
  while ($sw.Elapsed.TotalMinutes -lt 45) {
    try { $n = Invoke-Command -VMName $VmName -Credential $adm -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop; if ($n) { $up = $true; break } } catch { $lastErr = $_.Exception.Message }
    Start-Sleep -Seconds 20
  }
  if (-not $up) { Check 'W11.guest-up' 'FAIL' "no PowerShell Direct session as labadmin within 45 minutes: $lastErr"; Finish }
  Check 'W11.guest-up' 'PASS' "PowerShell Direct as labadmin after $([int]$sw.Elapsed.TotalSeconds) s"

  $g = Invoke-Command -VMName $VmName -Credential $adm -ArgumentList $GuestIp, $HostIp, $dns -ScriptBlock {
    param($ip, $gw, $dns)
    $out = @{}
    try {
      $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
      if (-not (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $ip -PrefixLength 24 -DefaultGateway $gw -ErrorAction Stop | Out-Null }
      Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $dns -ErrorAction Stop
      $out.net = "ip=$ip/24 gateway=$gw dns=$($dns -join ',')"
    } catch { $out.net = 'error: ' + $_.Exception.Message }
    Start-Sleep -Seconds 5
    try { $r = Invoke-WebRequest -Uri 'https://kiro.dev/' -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop; $out.web = "https://kiro.dev/ -> $($r.StatusCode)" } catch { $out.web = 'error: ' + $_.Exception.Message }
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $out.os = "$((Get-CimInstance Win32_OperatingSystem).Caption); EditionID=$($cv.EditionID); DisplayVersion=$($cv.DisplayVersion); build=$($cv.CurrentBuild).$($cv.UBR)"
    try { $t = Get-Tpm; $out.tpm = "TpmPresent=$($t.TpmPresent) TpmReady=$($t.TpmReady)" } catch { $out.tpm = 'error' }
    try { $out.sb = "SecureBoot=$(Confirm-SecureBootUEFI)" } catch { $out.sb = 'SecureBoot=error' }
    $out.users = (@(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }) -join ',')
    $out.admins = (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name -replace '^.*\\','' }) -join ',')
    $out.session = [string](Get-CimInstance Win32_ComputerSystem).UserName
    # The unattend file holds the passwords in plain text: remove it after the first start.
    Remove-Item -LiteralPath 'C:\Windows\Panther\unattend.xml' -Force -ErrorAction SilentlyContinue
    $out.unattend = (Test-Path -LiteralPath 'C:\Windows\Panther\unattend.xml')
    return $out
  }
  Check 'W11.guest-os' 'INFO' $g.os
  if ($g.tpm -match 'TpmPresent=True' -and $g.sb -match 'True') { Check 'W11.guest-tpm-secureboot' 'PASS' "$($g.tpm); $($g.sb)" } else { Check 'W11.guest-tpm-secureboot' 'FAIL' "$($g.tpm); $($g.sb)" }
  if ($g.web -match '-> 200') { Check 'W11.guest-network' 'PASS' "$($g.net); $($g.web)" } else { Check 'W11.guest-network' 'FAIL' "$($g.net); $($g.web)" }
  if (($g.users -match 'devuser') -and ($g.admins -notmatch 'devuser')) { Check 'W11.guest-accounts' 'PASS' "enabled local accounts: $($g.users); Administrators: $($g.admins); devuser is a standard user" } else { Check 'W11.guest-accounts' 'FAIL' "enabled: $($g.users); Administrators: $($g.admins)" }
  if ($g.session -match 'devuser') { Check 'W11.guest-session' 'PASS' "devuser is signed in at the console (automatic sign-in): $($g.session -replace '^.*\\','')" } else { Check 'W11.guest-session' 'INFO' "console session: [$($g.session)] (automatic sign-in may need one more restart)" }
  if (-not $g.unattend) { Check 'W11.guest-unattend-removed' 'PASS' 'C:\Windows\Panther\unattend.xml removed' } else { Check 'W11.guest-unattend-removed' 'FAIL' 'unattend.xml is still there' }

  if (-not (Get-VMSnapshot -VMName $VmName -Name 'clean' -ErrorAction SilentlyContinue)) {
    try { Checkpoint-VM -Name $VmName -SnapshotName 'clean' -ErrorAction Stop; Check 'W11.checkpoint' 'PASS' "checkpoint 'clean' (no Kiro, no policy) for the test phases" } catch { Check 'W11.checkpoint' 'FAIL' $_.Exception.Message }
  } else { Check 'W11.checkpoint' 'INFO' "checkpoint 'clean' exists already" }
  Finish
}

# ------------------------------------------------------------------------------------------------
'status' {
  Import-Module Hyper-V -ErrorAction SilentlyContinue
  $cs = Get-CimInstance Win32_ComputerSystem
  Check 'W11.host' 'INFO' "HypervisorPresent=$($cs.HypervisorPresent); ISO present=$(Test-Path -LiteralPath $Iso); free space C: $([int]((Get-PSDrive C).Free / 1GB)) GiB"
  $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
  if ($vm) { Check 'W11.vm' 'INFO' "state=$($vm.State); uptime=$($vm.Uptime); checkpoints=$(@(Get-VMSnapshot -VMName $VmName | ForEach-Object { $_.Name }) -join ',')" } else { Check 'W11.vm' 'INFO' 'no VM yet' }
  Finish
}

# ------------------------------------------------------------------------------------------------
# The W2 kit in the VM, run as labadmin through PowerShell Direct, with the switches its README gives.
{ $_ -in @('kit-baseline', 'kit-install', 'kit-policy') } {
  Import-Module Hyper-V -ErrorAction SilentlyContinue
  $admPw = Get-Secret 'win11-guest-admin'
  if (-not $admPw) { Check 'W11.kit' 'FAIL' 'no /kiro-fsi-test/win11-guest-admin parameter'; Finish }
  $s = $null
  try { $s = New-PSSession -VMName $VmName -Credential (New-Cred '.\labadmin' $admPw) -ErrorAction Stop } catch { Check 'W11.kit' 'FAIL' "no PowerShell Direct session: $($_.Exception.Message)"; Finish }
  # README step 1: the kit in a folder that only SYSTEM and Administrators can change.
  Invoke-Command -Session $s -ScriptBlock {
    if (Test-Path -LiteralPath 'C:\KiroW2Kit\repo') { Remove-Item -LiteralPath 'C:\KiroW2Kit\repo' -Recurse -Force }
    New-Item -ItemType Directory -Force -Path 'C:\KiroW2Kit\repo' | Out-Null
  }
  Copy-Item -ToSession $s -Path (Join-Path $RepoDir '*') -Destination 'C:\KiroW2Kit\repo' -Recurse -Force
  $prep = Invoke-Command -Session $s -ScriptBlock {
    $null = & icacls.exe 'C:\KiroW2Kit' /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 2>&1
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    $m = $wc.DownloadString('https://prod.download.desktop.kiro.dev/stable/metadata-win32-x64-system-stable.json') | ConvertFrom-Json
    $url = [string]@($m.releases)[0].updateTo.url
    if (-not $url.StartsWith('https://prod.download.desktop.kiro.dev/')) { return "manifest URL is not on the Kiro host: $url" }
    $exe = Join-Path 'C:\KiroW2Kit' ($url.Substring($url.LastIndexOf('/') + 1))
    if (-not (Test-Path -LiteralPath $exe)) { $wc.DownloadFile($url, $exe) }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $elev = (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return "ok|$exe|$($m.currentRelease)|$elev"
  }
  $pp = "$prep" -split '\|'
  if ($pp[0] -ne 'ok') { Check 'W11.kit' 'FAIL' "$prep"; Remove-PSSession $s; Finish }
  $Installer = $pp[1]
  Check 'W11.kit-copied' 'PASS' "kit in C:\KiroW2Kit\repo (SYSTEM and Administrators: full; Users: read); installer $(Split-Path -Leaf $Installer) (release $($pp[2])) downloaded from Kiro's update manifest; PowerShell Direct session elevated=$($pp[3])"
  $Signer = 'CN=Amazon.com, Inc., OU=AWS Kiro, O=Amazon.com, Inc., L=Seattle, S=Washington, C=US, SERIALNUMBER=2620453, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US'
  $runs = @()
  switch ($Phase) {
    'kit-baseline' { $runs = @(, @()) }
    'kit-install'  { $runs = @(@('-InstallerPath', $Installer), @('-InstallerPath', $Installer, '-Install', '-ExpectedSignerSubject', $Signer), @()) }
    'kit-policy'   { $runs = @(, @('-InstallPolicy', '-Wrappers', '-TamperTest')) }
  }
  foreach ($a in $runs) {
    Out-Line "NOTE kit run: Invoke-W2Checks.ps1 $(@($a | ForEach-Object { if ($_ -eq $Signer) { '<signer subject without quotes>' } else { $_ } }) -join ' ')"
    $lines = Invoke-Command -Session $s -ArgumentList (, $a) -ScriptBlock {
      param($kitArgs)
      & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\KiroW2Kit\repo\security-tests\windows-client\Invoke-W2Checks.ps1' @kitArgs 2>&1 | ForEach-Object { "$_" }
    }
    foreach ($l in @($lines)) { Out-Line "KIT $l" }
  }
  if ($Phase -eq 'kit-baseline') {
    $clean = Invoke-Command -Session $s -ScriptBlock {
      "ProgramData\Kiro=$(Test-Path -LiteralPath 'C:\ProgramData\Kiro'); HKLM\SOFTWARE\Policies\Kiro=$(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Kiro'); Default-profile hook file=$(Test-Path -LiteralPath 'C:\Users\Default\.kiro\hooks\banking-guards.windows.json')"
    }
    if ("$clean" -notmatch 'True') { Check 'W11.clean-device' 'PASS' "README step 2 clean-device check: $clean" } else { Check 'W11.clean-device' 'FAIL' "$clean" }
  }
  Remove-PSSession $s
  Finish
}

# ------------------------------------------------------------------------------------------------
# Phase WK (Kiro CLI) in the VM: windows-kiro-cli-suite.ps1 run as SYSTEM inside the guest through a
# one-time scheduled task. The guest has no AWS access, so the host reads the API key and hands it
# in as a file that only SYSTEM and Administrators can read; the suite removes it when it reads it.
'wk' {
  Import-Module Hyper-V -ErrorAction SilentlyContinue
  $admPw = Get-Secret 'win11-guest-admin'
  $key = Get-Secret 'kiro-api-key'
  if (-not $admPw) { Check 'W11.wk' 'FAIL' 'no /kiro-fsi-test/win11-guest-admin parameter'; Finish }
  $s = $null
  try { $s = New-PSSession -VMName $VmName -Credential (New-Cred '.\labadmin' $admPw) -ErrorAction Stop } catch { Check 'W11.wk' 'FAIL' "no PowerShell Direct session: $($_.Exception.Message)"; Finish }
  Invoke-Command -Session $s -ScriptBlock {
    New-Item -ItemType Directory -Force -Path 'C:\kiro-test' | Out-Null
    if (Test-Path -LiteralPath 'C:\kiro-test\repo') { Remove-Item -LiteralPath 'C:\kiro-test\repo' -Recurse -Force }
    New-Item -ItemType Directory -Force -Path 'C:\kiro-test\repo', 'C:\kiro-test\in' | Out-Null
    $null = & icacls.exe 'C:\kiro-test\in' /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
  }
  Copy-Item -ToSession $s -Path (Join-Path $RepoDir '*') -Destination 'C:\kiro-test\repo' -Recurse -Force
  # Kiro CLI 3.5.0 links MSVCP140/VCRUNTIME140(_1); a clean Windows 11 has no Visual C++ runtime and its
  # MSI does not bring one (kiro-cli.exe exits 0xC0000135). W11_WK_VCREDIST=1 installs Microsoft's
  # Visual C++ 2015-2022 Redistributable (x64) first, after its signature is checked.
  $vc = Invoke-Command -Session $s -ScriptBlock {
    $k = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
    $before = (Get-ItemProperty $k -ErrorAction SilentlyContinue).Version
    "before=$(if ($before) { $before } else { 'none' })"
  }
  Check 'W11.vcredist-before' 'INFO' "Visual C++ 14 x64 runtime in the VM: $vc"
  if ("$env:W11_WK_VCREDIST" -eq '1') {
    $r = Invoke-Command -Session $s -ScriptBlock {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      $f = 'C:\kiro-test\in\vc_redist.x64.exe'
      (New-Object System.Net.WebClient).DownloadFile('https://aka.ms/vs/17/release/vc_redist.x64.exe', $f)
      $sig = Get-AuthenticodeSignature -LiteralPath $f
      $subj = [string]$sig.SignerCertificate.Subject
      if ($sig.Status -ne 'Valid' -or $subj -notmatch '^CN=Microsoft Corporation,') { return "refused: status=$($sig.Status); signer=$subj" }
      $ver = (Get-Item $f).VersionInfo.ProductVersion
      $p = Start-Process -FilePath $f -ArgumentList '/install /quiet /norestart' -Wait -PassThru
      $after = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue).Version
      Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
      "ok|exit=$($p.ExitCode); package $ver; signer=$($subj.Split(',')[0]); runtime now=$after; vcruntime140.dll=$(Test-Path (Join-Path $env:SystemRoot 'System32\vcruntime140.dll'))"
    }
    if ("$r" -like 'ok|*') { Check 'W11.vcredist' 'PASS' ("Visual C++ 2015-2022 Redistributable x64 from aka.ms/vs/17/release, Authenticode Valid: " + ("$r".Substring(3))) }
    else { Check 'W11.vcredist' 'FAIL' "$r"; Remove-PSSession $s; Finish }
  }
  $recheck = "$env:W11_WK_RECHECK"
  $started = Invoke-Command -Session $s -ArgumentList $key, $recheck -ScriptBlock {
    param($k, $rc)
    if ($k) { [System.IO.File]::WriteAllText('C:\kiro-test\in\key.txt', $k, (New-Object System.Text.UTF8Encoding($false))) }
    $run = @(
      "`$env:KIRO_WK_KEY_FILE = 'C:\kiro-test\in\key.txt'",
      "`$env:KIRO_WK_RECHECK = '$rc'",
      "& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\kiro-test\repo\security-tests\aws-integration\windows-kiro-cli-suite.ps1 -RepoDir C:\kiro-test\repo *> C:\kiro-test\in\wk.out",
      "Set-Content -LiteralPath C:\kiro-test\in\wk.rc -Value `$LASTEXITCODE"
    ) -join "`r`n"
    Set-Content -LiteralPath 'C:\kiro-test\in\run.ps1' -Value $run -Encoding ASCII
    Remove-Item -LiteralPath 'C:\kiro-test\in\wk.out', 'C:\kiro-test\in\wk.rc' -Force -ErrorAction SilentlyContinue
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\kiro-test\in\run.ps1'
    $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName 'KiroWK' -Action $a -Settings $st -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName 'KiroWK'
    return 'ok'
  }
  $key = $null
  if ("$started" -ne 'ok') { Check 'W11.wk' 'FAIL' "the task did not start: $started"; Remove-PSSession $s; Finish }
  Out-Line "NOTE phase WK started in the VM as SYSTEM (re-check=$recheck)"
  $deadline = (Get-Date).AddMinutes(110)
  do {
    Start-Sleep -Seconds 30
    $st = Invoke-Command -Session $s -ScriptBlock { "$((Get-ScheduledTask -TaskName 'KiroWK').State)|$(Test-Path -LiteralPath 'C:\kiro-test\in\wk.rc')" }
  } while (("$st" -notmatch '\|True$') -and ((Get-Date) -lt $deadline))
  $out = Invoke-Command -Session $s -ScriptBlock {
    $o = if (Test-Path -LiteralPath 'C:\kiro-test\in\wk.out') { Get-Content -LiteralPath 'C:\kiro-test\in\wk.out' } else { @('no output file') }
    Remove-Item -LiteralPath 'C:\kiro-test\in\key.txt', 'C:\kiro-test\wk\secret\key.txt' -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'KiroWK' -Confirm:$false -ErrorAction SilentlyContinue
    $o
  }
  foreach ($l in @($out)) { Out-Line "WK $l" }
  if ("$st" -notmatch '\|True$') { Check 'W11.wk' 'FAIL' "the suite did not finish in 110 minutes (task state: $st)" }
  else { Check 'W11.wk' 'INFO' 'phase WK ended in the VM; its result is the PHASE WK line above' }
  Remove-PSSession $s
  Finish
}

default { Check 'W11.phase' 'FAIL' "unknown phase '$Phase' (host, iso, vm, status, kit-baseline, kit-install, kit-policy, wk)"; Finish }
}
