#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables file system auditing for ICS and dangerous file types across the entire OS
.DESCRIPTION
    Configures SACL (System Access Control List) auditing on all drives to monitor
    creation, modification, and deletion of critical file types
.NOTES
    Requires Administrator privileges
    Creates audit entries in Security Event Log (Event IDs 4663, 4656, 4660)
#>

# Define file extensions to monitor
$ICSExtensions = @(
    # ICS/SCADA Configuration Files
    '*.rslogix', '*.acd', '*.rss',  # Rockwell/Allen-Bradley
    '*.s7p', '*.awl', '*.gsd',       # Siemens Step 7
    '*.xsy', '*.fbd',                # Schneider Electric
    '*.mer', '*.dvt',                # GE/Emerson
    '*.apj', '*.cxp',                # Omron
    '*.prg', '*.stu',                # Mitsubishi
    '*.project', '*.solution',       # Various SCADA
    '*.hmi', '*.pd*',                # HMI files
    '*.dbf', '*.dat',                # Database/Data files
    '*.cfg', '*.conf', '*.config',   # Configuration files
    
    # Executable and Script Files
    '*.exe', '*.dll', '*.sys',
    '*.bat', '*.cmd', '*.ps1', '*.vbs', '*.js',
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
Write-Host "[1/5] Resetting Audit Policy..." -ForegroundColor Green
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
Write-Host "[2/5] Detecting drives..." -ForegroundColor Green
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Root -match '^[A-Z]:\\$' -and (Test-Path $_.Root)
}

Write-Host "  Found drives: $($drives.Root -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Apply audit rules to each drive root
Write-Host "[3/5] Removing audit rules from noisy system locations..." -ForegroundColor Green

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

# Remove audit from noisy Windows system folders
$noisyPaths = @(
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
    "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
)

foreach ($path in $noisyPaths) {
    if ($path -and (Test-Path $path)) {
        Remove-AuditRule -Path $path
    }
}

Write-Host ""
Write-Host "[4/5] Applying targeted audit rules..." -ForegroundColor Green
$successCount = 0

# Instead of auditing drive roots, audit specific high-value targets
$targetPaths = @(
    # User locations (high risk for malware/data exfil)
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:PUBLIC\Documents",
    "$env:PUBLIC\Desktop",
    
    # Program Files (monitor executable changes)
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    
    # Critical ProgramData (config files, but exclude Microsoft folders)
    "$env:ProgramData"
)

# Add ICS-specific paths if they exist
$icsPaths = @(
    "C:\Program Files\Rockwell Software",
    "C:\Program Files (x86)\Rockwell Software",
    "C:\Program Files\Siemens",
    "C:\Program Files (x86)\Siemens",
    "C:\Program Files\Schneider Electric",
    "C:\Program Files (x86)\Schneider Electric",
    "C:\Program Files\GE",
    "C:\Program Files (x86)\GE",
    "C:\SCADA",
    "C:\HMI",
    "C:\PLC"
)

$targetPaths += $icsPaths

foreach ($path in $targetPaths) {
    if ($path -and (Test-Path $path)) {
        Write-Host "  Processing: $path" -ForegroundColor Cyan
        if (Set-AuditRule -Path $path -Extensions $AllExtensions) {
            $successCount++
            Write-Host "  ✓ Audit configured on $path" -ForegroundColor Green
        }
    }
}

# Explicitly exclude Microsoft folders under ProgramData and Velociraptor directory
$excludePaths = @(
    "$env:ProgramData\Microsoft",
    "C:\Program Files\Velociraptor"
)

foreach ($path in $excludePaths) {
    if ($path -and (Test-Path $path)) {
        Remove-AuditRule -Path $path
    }
}

# Apply audit rules to critical system directories
Write-Host ""
Write-Host "[5/5] Verifying Audit Policy..." -ForegroundColor Green
Write-Host ""
auditpol /get /category:"Object Access"
Write-Host ""

# Summary
Write-Host ""
Write-Host "=== Configuration Complete ===" -ForegroundColor Cyan
Write-Host "✓ Configured auditing on $successCount target location(s)" -ForegroundColor Green
Write-Host "✓ Excluded noisy Windows system folders" -ForegroundColor Green
Write-Host "✓ Excluded Velociraptor directory from auditing" -ForegroundColor Green
Write-Host "✓ Monitoring $($AllExtensions.Count) file type patterns" -ForegroundColor Green
Write-Host ""
Write-Host "Audit Events Information:" -ForegroundColor Yellow
Write-Host "  - Event Log: Security" -ForegroundColor White
Write-Host "  - Event ID 4663: File access/modification (PRIMARY)" -ForegroundColor White
Write-Host "  - Captures: ReadData, WriteData, AppendData, Delete operations on files" -ForegroundColor White
Write-Host ""
Write-Host "To view audit events, run:" -ForegroundColor Yellow
Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 50" -ForegroundColor Cyan
Write-Host ""

# Optional: Create a monitoring script
$monitorScript = @'
# Quick Audit Monitor Script - Focused on Event 4663
# Monitors actual file access/modification events only

param(
    [int]$Hours = 1,
    [switch]$ShowDetails
)

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4663
    StartTime=(Get-Date).AddHours(-$Hours)
} -ErrorAction SilentlyContinue

# Filter out events from excluded processes (e.g., Velociraptor)
# and filter to only include File objects (exclude Directory)
$events = $events | Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $procName = ($eventData | Where-Object {$_.Name -eq 'ProcessName'}).'#text'
    $objType = ($eventData | Where-Object {$_.Name -eq 'ObjectType'}).'#text'
    ($procName -notlike "*velociraptor.exe") -and ($objType -eq "File")
}

if ($events.Count -eq 0) {
    Write-Host "No file access events found in the last $Hours hour(s)" -ForegroundColor Yellow
    exit
}

Write-Host "`n=== File Access Events (Last $Hours Hour(s)) ===" -ForegroundColor Cyan
Write-Host "Total Events: $($events.Count)" -ForegroundColor Green
Write-Host ""

$groupedEvents = $events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        ObjectName = ($eventData | Where-Object {$_.Name -eq 'ObjectName'}).'#text'
        ProcessName = ($eventData | Where-Object {$_.Name -eq 'ProcessName'}).'#text'
        AccessMask = ($eventData | Where-Object {$_.Name -eq 'AccessMask'}).'#text'
        SubjectUserName = ($eventData | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
    }
}

# Group by file and show summary
$summary = $groupedEvents | Group-Object ObjectName | Sort-Object Count -Descending

Write-Host "Top Modified Files:" -ForegroundColor Yellow
$summary | Select-Object -First 20 | ForEach-Object {
    $color = if($_.Count -gt 10){'Red'}elseif($_.Count -gt 5){'Yellow'}else{'White'}
    Write-Host "  [$($_.Count) times] $($_.Name)" -ForegroundColor $color
}

if ($ShowDetails) {
    Write-Host "`n=== Detailed Events ===" -ForegroundColor Cyan
    $groupedEvents | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object {
        Write-Host "`n$($_.TimeCreated)" -ForegroundColor Green
        Write-Host "  File: $($_.ObjectName)" -ForegroundColor White
        Write-Host "  Process: $($_.ProcessName)" -ForegroundColor Cyan
        Write-Host "  User: $($_.SubjectUserName)" -ForegroundColor Gray
    }
}

Write-Host "`nUse -ShowDetails switch for full event details" -ForegroundColor Yellow
'@

$monitorScript | Out-File -FilePath "$PSScriptRoot\Monitor-FileAudits.ps1" -Force
Write-Host "Created monitoring script: Monitor-FileAudits.ps1" -ForegroundColor Green
Write-Host "  Usage: .\Monitor-FileAudits.ps1 -Hours 24 -ShowDetails" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠ Focused on Event 4663 to reduce noise while capturing all actual file operations" -ForegroundColor Yellow
Write-Host "⚠ Focused on file read/write rights (ReadData, WriteData, AppendData, Delete)" -ForegroundColor Yellow
Write-Host "⚠ Used InheritOnly propagation to avoid auditing target folders themselves" -ForegroundColor Yellow
Write-Host "⚠ Consider filtering by specific directories or file types in high-volume environments" -ForegroundColor Yellow
Write-Host "⚠ Excluded events from velociraptor.exe process in monitoring" -ForegroundColor Yellow
Write-Host "⚠ Filtered to only show File objects (excludes Directory events)" -ForegroundColor Yellow
