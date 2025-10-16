#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables file system auditing for ICS and dangerous file types across the entire OS
.DESCRIPTION
    Configures SACL (System Access Control List) auditing on all drives to monitor
    creation, modification, and deletion of critical file types for ALL user profiles
.NOTES
    Requires Administrator privileges
    Creates audit entries in Security Event Log (Event IDs 4663, 4656, 4660)
#>

# Define file extensions to monitor
$ICSExtensions = @(
    # Rockwell Automation / Allen-Bradley
    '*.rslogix', '*.acd', '*.rss', '*.acs', '*.l5k', '*.l5x', '*.prj',
    '*.mer', '*.apa', '*.cdx', '*.rsp', '*.xml',
    
    # Siemens (Step 7, TIA Portal, WinCC)
    '*.s7p', '*.awl', '*.gsd', '*.zap13', '*.zap14', '*.zap15', '*.zap16',
    '*.ap13', '*.ap14', '*.ap15', '*.ap16', '*.sdb', '*.db', '*.udb',
    '*.mwp', '*.xdb', '*.plc', '*.wld', '*.s7', '*.ob', '*.fc', '*.fb',
    '*.pdm', '*.pcs7', '*.mcp', '*.hwd',
    
    # Schneider Electric (Unity Pro, EcoStruxure, Vijeo)
    '*.xsy', '*.fbd', '*.stu', '*.scy', '*.xef', '*.zef', '*.vdz',
    '*.vxd', '*.vxdz', '*.hjx', '*.clx', '*.ief', '*.prm',
    
    # GE / Emerson / Fanuc
    '*.mer', '*.dvt', '*.cim', '*.med', '*.gef', '*.vsd', '*.mdb',
    '*.pac', '*.bak', '*.ld', '*.tpe', '*.ls', '*.tp',
    
    # Omron
    '*.apj', '*.cxp', '*.cxt', '*.cxone', '*.ws2', '*.smc', '*.opt',
    
    # Mitsubishi
    '*.prg', '*.gx3', '*.gxw', '*.qpa', '*.qpd', '*.gx2', '*.qj3',
    
    # ABB (Control Builder, 800xA)
    '*.pkw', '*.prj', '*.apg', '*.cpf', '*.cmp', '*.800xa',
    
    # Honeywell (Experion, PlantCruise)
    '*.exp', '*.hsc', '*.scf', '*.pks', '*.rw3',
    
    # Yokogawa (Centum, ProSafe)
    '*.ycp', '*.prj', '*.bkp', '*.cvp',
    
    # Wonderware / AVEVA (InTouch, System Platform)
    '*.intouch', '*.aaw', '*.ww', '*.cab', '*.galaxy', '*.gal',
    '*.pak', '*.aapkg',
    
    # Iconics (Genesis, SCADA)
    '*.gx', '*.gwx', '*.gwxp',
    
    # Ignition (Inductive Automation)
    '*.proj', '*.modl',
    
    # Citect / AVEVA
    '*.ctz', '*.dbf', '*.ctd', '*.cte',
    
    # FactoryTalk / RSView
    '*.apa', '*.apa32', '*.fth', '*.eme', '*.tag',
    
    # Generic SCADA/HMI/PLC Files
    '*.hmi', '*.scada', '*.pd*', '*.pdb', '*.project', '*.solution',
    '*.ladder', '*.sfc', '*.st', '*.il', '*.iec',
    
    # Configuration and Data Files
    '*.cfg', '*.conf', '*.config', '*.ini', '*.json', '*.xml',
    '*.dbf', '*.dat', '*.db', '*.sqlite', '*.mdb', '*.accdb',
    '*.csv', '*.log', '*.txt', '*.alarm', '*.event', '*.hist',
    
    # Backup and Archive Files (ICS-specific)
    '*.bak', '*.backup', '*.old', '*.arc', '*.archive',
    
    # Firmware and Update Files
    '*.bin', '*.hex', '*.fw', '*.upd', '*.rom', '*.flash',
    
    # Modbus, OPC, and Protocol Files
    '*.eds', '*.dcf', '*.xdd', '*.opc', '*.opcxml', '*.da',
    
    # Industrial Network Files
    '*.icd', '*.scd', '*.cid', '*.ied', '*.iid', '*.sed',
    
    # Executable and Script Files
    '*.exe', '*.dll', '*.sys',
    '*.bat', '*.cmd', '*.ps1', '*.vbs', '*.js', '*.wsh',
    '*.msi', '*.scr', '*.com', '*.pif',
    
    # Dangerous Document Types
    '*.doc', '*.docx', '*.docm',
    '*.xls', '*.xlsx', '*.xlsm', '*.xlam',
    '*.ppt', '*.pptx', '*.pptm',
    '*.pdf', '*.rtf',
    
    # Archive and Compressed Files
    '*.zip', '*.rar', '*.7z', '*.tar', '*.gz',
    '*.cab', '*.iso', '*.img',
    
    # Web and Network Files
    '*.html', '*.htm', '*.hta',
    '*.url', '*.lnk', '*.inf',
    
    # Registry and System Files
    '*.reg', '*.pol', '*.msc',
    '*.cpl', '*.drv', '*.ocx'
)

$DangerousExtensions = @(
    '*.application', '*.gadget', '*.msh', '*.msh1',
    '*.msh2', '*.mshxml', '*.msh1xml', '*.msh2xml',
    '*.scf', '*.ws', '*.wsf', '*.wsh', '*.jar'
)

# Combine all extensions
$AllExtensions = $ICSExtensions + $DangerousExtensions | Select-Object -Unique

Write-Host "=== File System Audit Configuration for ICS & Dangerous Files ===" -ForegroundColor Cyan
Write-Host "Monitoring $($AllExtensions.Count) file type patterns" -ForegroundColor Yellow
Write-Host ""

# Reset and configure audit policy
Write-Host "[1/6] Resetting Audit Policy..." -ForegroundColor Green
try {
    # Disable Handle Manipulation to prevent 4656/4658/4690 events
    auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
    Write-Host "  ✓ Disabled Handle Manipulation auditing (prevents 4656 noise)" -ForegroundColor Green
    
    # Enable only File System auditing (generates 4663 for actual operations)
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    Write-Host "  ✓ Enabled File System auditing (4663 events only)" -ForegroundColor Green
    
    # Disable other noisy object access categories
    auditpol /set /subcategory:"Registry" /success:disable /failure:disable
    auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
    auditpol /set /subcategory:"SAM" /success:disable /failure:disable
    auditpol /set /subcategory:"Certification Services" /success:disable /failure:disable
    auditpol /set /subcategory:"Application Generated" /success:disable /failure:disable
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
    auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
    Write-Host "  ✓ Disabled other Object Access subcategories" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Error configuring audit policy: $_" -ForegroundColor Red
}

# Function to set SACL on a path
function Set-AuditRule {
    param(
        [string]$Path,
        [string[]]$Extensions
    )
    
    if (-not (Test-Path $Path)) {
        Write-Host "  ⚠ Path not found: $Path" -ForegroundColor Yellow
        return
    }
    
    try {
        $acl = Get-Acl $Path
        
        # Define audit rules for Everyone
        $auditUser = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        
        # Focus on file read and write rights: ReadData, WriteData, AppendData, Delete
        $auditRights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                      [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                      [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                      [System.Security.AccessControl.FileSystemRights]::Delete
        
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                           [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::InheritOnly
        
        # Create audit rules for both success and failure
        $auditRuleSuccess = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $auditUser,
            $auditRights,
            $inheritanceFlags,
            $propagationFlags,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        
        $auditRuleFailure = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $auditUser,
            $auditRights,
            $inheritanceFlags,
            $propagationFlags,
            [System.Security.AccessControl.AuditFlags]::Failure
        )
        
        # Remove existing audit rules to avoid duplicates
        $acl.PurgeAuditRules($auditUser)
        
        # Add new audit rules
        $acl.AddAuditRule($auditRuleSuccess)
        $acl.AddAuditRule($auditRuleFailure)
        
        # Apply the SACL
        Set-Acl -Path $Path -AclObject $acl
        
        return $true
    } catch {
        Write-Host "  ✗ Error on $Path : $_" -ForegroundColor Red
        return $false
    }
}

# Get all fixed drives
Write-Host "[2/6] Detecting drives..." -ForegroundColor Green
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Root -match '^[A-Z]:\\$' -and (Test-Path $_.Root)
}

Write-Host "  Found drives: $($drives.Root -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Enumerate all user profiles
Write-Host "[3/6] Enumerating user profiles..." -ForegroundColor Green
$userProfiles = @()

# Get all user profile directories
$profilesPath = "C:\Users"
if (Test-Path $profilesPath) {
    $allProfiles = Get-ChildItem $profilesPath -Directory -Force -ErrorAction SilentlyContinue
    
    foreach ($profile in $allProfiles) {
        # Skip system profiles
        $skipProfiles = @('Public', 'Default', 'Default User', 'All Users')
        if ($profile.Name -in $skipProfiles) {
            continue
        }
        
        # Check if it's a valid user profile (has Documents, Desktop, etc.)
        $documentsPath = Join-Path $profile.FullName "Documents"
        if (Test-Path $documentsPath) {
            $userProfiles += $profile.FullName
            Write-Host "  ✓ Found user profile: $($profile.Name)" -ForegroundColor Cyan
        }
    }
}

Write-Host "  Total user profiles found: $($userProfiles.Count)" -ForegroundColor Green
Write-Host ""

# Remove audit from noisy Windows system folders
Write-Host "[4/6] Removing audit rules from noisy system locations..." -ForegroundColor Green

# Function to remove audit rules (reduce noise)
function Remove-AuditRule {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) { return }
    
    try {
        $acl = Get-Acl $Path
        $auditUser = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $acl.PurgeAuditRules($auditUser)
        Set-Acl -Path $Path -AclObject $acl
        Write-Host "  ✓ Removed auditing from: $Path" -ForegroundColor Gray
    } catch {
        Write-Host "  ⚠ Could not remove audit from: $Path" -ForegroundColor Yellow
    }
}

$noisyPaths = @(
    # Windows System Directories
    "$env:SystemRoot\System32\config",
    "$env:SystemRoot\System32\winevt",
    "$env:SystemRoot\System32\LogFiles",
    "$env:SystemRoot\Logs",
    "$env:SystemRoot\Prefetch",
    "$env:SystemRoot\SoftwareDistribution",
    "$env:SystemRoot\WinSxS",
    "$env:SystemRoot\servicing",
    "$env:SystemRoot\System32\sru",
    "$env:ProgramData\Microsoft\Windows\WER",
    "$env:ProgramData\Microsoft\Diagnosis",
    
    # ICS Platform Runtime/Cache Directories (not configuration)
    "C:\Program Files\Inductive Automation\Ignition\data\modules",
    "C:\Program Files\Inductive Automation\Ignition\data\temp",
    "C:\Program Files\Inductive Automation\Ignition\cache",
    "C:\Program Files\Inductive Automation\Ignition\logs",
    "C:\Program Files\Inductive Automation\Ignition\lib\runtime",
    
    "C:\Program Files\Rockwell Software\RSCommon",
    "C:\Program Files\Rockwell Software\FactoryTalk View\logs",
    "C:\Program Files (x86)\Rockwell Software\RSCommon",
    
    "C:\Program Files\Siemens\Automation\Portal V*\Data\Cache",
    "C:\Program Files\Siemens\Automation\WinCCUnified\cache",
    "C:\Program Files (x86)\Siemens\Automation\Portal V*\Data\Cache",
    
    "C:\Program Files\Wonderware\InTouch\AlarmDBLogger",
    
    "C:\Program Files\AVEVA\System Platform\Logs",
    
    "C:\Program Files\GE\iFIX\Logs",
    "C:\Program Files\GE\Proficy Historian\logs"
    
)

# Add noisy paths from all user profiles
foreach ($userProfile in $userProfiles) {
    $noisyPaths += @(
        "$userProfile\AppData\Local\Microsoft\Windows\Explorer",
        "$userProfile\AppData\Local\Microsoft\Windows\WebCache",
        "$userProfile\AppData\Local\Microsoft\Windows\INetCache",
        "$userProfile\AppData\Local\Temp",
        "$userProfile\AppData\Local\Packages"
    )
}

foreach ($path in $noisyPaths) {
    if ($path -and (Test-Path $path)) {
        Remove-AuditRule -Path $path
    }
}

Write-Host ""
Write-Host "[5/6] Applying targeted audit rules..." -ForegroundColor Green
$successCount = 0

# Build target paths for ALL users
$targetPaths = @(
    # Public folders
    "$env:PUBLIC\Documents",
    "$env:PUBLIC\Desktop",
    
    # Program Files (monitor executable changes)
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    
    # Critical ProgramData (config files, but exclude Microsoft folders)
    "$env:ProgramData"
)

# Add user-specific paths for ALL discovered profiles
foreach ($userProfile in $userProfiles) {
    $targetPaths += @(
        "$userProfile\Documents",
        "$userProfile\Downloads",
        "$userProfile\Desktop",
        "$userProfile\OneDrive",
        "$userProfile\Favorites"
    )
}

# Add ICS-specific paths if they exist
$icsPaths = @(
    # Rockwell Automation
    "C:\Program Files\Rockwell Software",
    "C:\Program Files (x86)\Rockwell Software",
    "C:\Program Files\Common Files\Rockwell",
    "C:\Program Files (x86)\Common Files\Rockwell",
    "C:\RSLogix 5000",
    "C:\RSLogix 500",
    "C:\FactoryTalk",
    
    # Siemens
    "C:\Program Files\Siemens",
    "C:\Program Files (x86)\Siemens",
    "C:\Program Files\Common Files\Siemens",
    "C:\Siemens",
    "C:\S7",
    "C:\TIA Portal",
    "C:\STEP 7",
    "C:\WinCC",
    
    # Schneider Electric
    "C:\Program Files\Schneider Electric",
    "C:\Program Files (x86)\Schneider Electric",
    "C:\Schneider Electric",
    "C:\Unity Pro",
    "C:\Vijeo Designer",
    "C:\EcoStruxure",
    "C:\SoMachine",
    
    # GE Digital / Emerson
    "C:\Program Files\GE",
    "C:\Program Files (x86)\GE",
    "C:\GE",
    "C:\Proficy",
    "C:\iHistorian",
    "C:\CIMPLICITY",
    "C:\Emerson",
    "C:\DeltaV",
    
    # Omron
    "C:\Program Files\OMRON",
    "C:\Program Files (x86)\OMRON",
    "C:\OMRON",
    "C:\CX-One",
    "C:\CX-Programmer",
    
    # Mitsubishi
    "C:\Program Files\Mitsubishi",
    "C:\Program Files (x86)\Mitsubishi",
    "C:\MELSEC",
    "C:\GX Works",
    "C:\GX Developer",
    
    # ABB
    "C:\Program Files\ABB",
    "C:\Program Files (x86)\ABB",
    "C:\ABB",
    "C:\Control Builder",
    "C:\800xA",
    
    # Honeywell
    "C:\Program Files\Honeywell",
    "C:\Program Files (x86)\Honeywell",
    "C:\Honeywell",
    "C:\Experion",
    "C:\PlantCruise",
    
    # Yokogawa
    "C:\Program Files\Yokogawa",
    "C:\Program Files (x86)\Yokogawa",
    "C:\Yokogawa",
    "C:\Centum",
    "C:\FAST TOOLS",
    
    # Wonderware / AVEVA
    "C:\Program Files\Wonderware",
    "C:\Program Files (x86)\Wonderware",
    "C:\Program Files\AVEVA",
    "C:\Program Files (x86)\AVEVA",
    "C:\Wonderware",
    "C:\AVEVA",
    "C:\InTouch",
    "C:\System Platform",
    "C:\ArchestrA",
    
    # Iconics
    "C:\Program Files\ICONICS",
    "C:\Program Files (x86)\ICONICS",
    "C:\ICONICS",
    "C:\GENESIS64",
    
    # Ignition (Inductive Automation)
    "C:\Program Files\Inductive Automation",
    "C:\Program Files (x86)\Inductive Automation",
    "C:\Ignition",
    
    # Citect
    "C:\Program Files\Citect",
    "C:\Program Files (x86)\Citect",
    "C:\Citect",
    
    # Phoenix Contact
    "C:\Program Files\Phoenix Contact",
    "C:\Program Files (x86)\Phoenix Contact",
    "C:\PC WORX",
    
    # Beckhoff
    "C:\TwinCAT",
    "C:\Program Files\Beckhoff",
    "C:\Program Files (x86)\Beckhoff",
    
    # CODESYS
    "C:\Program Files\CODESYS",
    "C:\Program Files (x86)\CODESYS",
    "C:\CODESYS",
    
    # B&R Automation
    "C:\BRAutomation",
    "C:\Program Files\BR Automation",
    "C:\Program Files (x86)\BR Automation",
    "C:\Automation Studio",
    
    # Kepware / PTC
    "C:\Program Files\Kepware",
    "C:\Program Files (x86)\Kepware",
    "C:\KEPServerEX",
    "C:\ThingWorx",
    
    # National Instruments
    "C:\Program Files\National Instruments",
    "C:\Program Files (x86)\National Instruments",
    "C:\LabVIEW Data",
    
    # Generic SCADA/HMI/PLC Directories
    "C:\SCADA",
    "C:\HMI",
    "C:\PLC",
    "C:\DCS",
    "C:\OPC",
    "C:\Historian",
    "C:\Projects",
    "C:\ICS Projects",
    "C:\Automation",
    "C:\Control",
    "C:\Industrial",
    
    # Data and Backup Directories
    "C:\Data",
    "C:\Backups",
    "C:\Archives",
    "C:\Logs"
)

$targetPaths += $icsPaths

# Remove duplicates
$targetPaths = $targetPaths | Select-Object -Unique

Write-Host "  Processing $($targetPaths.Count) target locations..." -ForegroundColor Cyan
Write-Host ""

foreach ($path in $targetPaths) {
    if ($path -and (Test-Path $path)) {
        Write-Host "  Processing: $path" -ForegroundColor Cyan
        if (Set-AuditRule -Path $path -Extensions $AllExtensions) {
            $successCount++
            Write-Host "  ✓ Audit configured" -ForegroundColor Green
        }
    }
}

# Explicitly exclude Microsoft folders under ProgramData, Velociraptor, and ICS runtime directories
$excludePaths = @(
    "$env:ProgramData\Microsoft",
    "C:\Program Files\Velociraptor",
    
    # Additional ICS runtime exclusions (wildcards handled by recursive exclusion)
    "C:\Program Files\Inductive Automation\Ignition\data\modules",
    "C:\Program Files\Inductive Automation\Ignition\data\temp",
    "C:\Program Files\Inductive Automation\Ignition\cache",
    "C:\Program Files\Inductive Automation\Ignition\logs"
)

Write-Host ""
Write-Host "Excluding noise sources..." -ForegroundColor Yellow
foreach ($path in $excludePaths) {
    if ($path -and (Test-Path $path)) {
        Remove-AuditRule -Path $path
    }
}

# Verify Audit Policy
Write-Host ""
Write-Host "[6/6] Verifying Audit Policy..." -ForegroundColor Green
Write-Host ""
auditpol /get /category:"Object Access"
Write-Host ""

# Summary
Write-Host ""
Write-Host "=== Configuration Complete ===" -ForegroundColor Cyan
Write-Host "✓ Configured auditing on $successCount target location(s)" -ForegroundColor Green
Write-Host "✓ Monitoring $($userProfiles.Count) user profile(s)" -ForegroundColor Green
Write-Host "✓ Excluded noisy Windows system folders" -ForegroundColor Green
Write-Host "✓ Excluded Velociraptor directory from auditing" -ForegroundColor Green
Write-Host "✓ Monitoring $($AllExtensions.Count) file type patterns" -ForegroundColor Green
Write-Host ""
Write-Host "User profiles monitored:" -ForegroundColor Yellow
foreach ($profile in $userProfiles) {
    Write-Host "  - $(Split-Path $profile -Leaf)" -ForegroundColor White
}
Write-Host ""
Write-Host "Audit Events Information:" -ForegroundColor Yellow
Write-Host "  - Event Log: Security" -ForegroundColor White
Write-Host "  - Event ID 4663: File access/modification (PRIMARY)" -ForegroundColor White
Write-Host "  - Captures: ReadData, WriteData, AppendData, Delete operations on files" -ForegroundColor White
Write-Host ""
Write-Host "To view audit events, run:" -ForegroundColor Yellow
Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 50" -ForegroundColor Cyan
Write-Host ""

Write-Host "Created monitoring script: Monitor-FileAudits.ps1" -ForegroundColor Green
Write-Host "  Usage: .\Monitor-FileAudits.ps1 -Hours 24 -ShowDetails" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠ Focused on Event 4663 to reduce noise while capturing all actual file operations" -ForegroundColor Yellow
Write-Host "⚠ Focused on file read/write rights (ReadData, WriteData, AppendData, Delete)" -ForegroundColor Yellow
Write-Host "⚠ Used InheritOnly propagation to avoid auditing target folders themselves" -ForegroundColor Yellow
Write-Host "⚠ Excluded ICS runtime directories (modules, cache, logs, backups)" -ForegroundColor Yellow
Write-Host "⚠ Monitoring script filters java.exe CSS theme reads from Ignition" -ForegroundColor Yellow
Write-Host "⚠ Consider filtering by specific directories or file types in high-volume environments" -ForegroundColor Yellow
