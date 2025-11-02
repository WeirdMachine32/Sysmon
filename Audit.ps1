#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables comprehensive file system auditing across the entire OS with NO EXCLUSIONS
.DESCRIPTION
    Configures SACL (System Access Control List) auditing on all drives to monitor
    ALL file operations for ALL users with NO filtering or exclusions
.NOTES
    Requires Administrator privileges
    Creates audit entries in Security Event Log (Event ID 4663 only)
    WARNING: This will generate MASSIVE amounts of audit data
#>

Write-Host "=== COMPREHENSIVE File System Audit - NO EXCLUSIONS ===" -ForegroundColor Red
Write-Host "WARNING: This will generate MASSIVE amounts of audit data!" -ForegroundColor Yellow
Write-Host "WARNING: Your Security Event Log may fill up rapidly!" -ForegroundColor Yellow
Write-Host "Monitoring ALL files and directories - NO FILTERS" -ForegroundColor Yellow
Write-Host ""

# Configure audit policy - Only File System for 4663 events
Write-Host "[1/3] Configuring Audit Policy for 4663 events only..." -ForegroundColor Green
try {
    # Disable Handle Manipulation to prevent 4656/4658/4690 events
    auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
    Write-Host "  - Disabled Handle Manipulation auditing" -ForegroundColor Green
    
    # Enable only File System auditing (generates 4663 for actual operations)
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    Write-Host "  - Enabled File System auditing (4663 events only)" -ForegroundColor Green
    
    # Disable other noisy object access categories
    auditpol /set /subcategory:"Registry" /success:disable /failure:disable
    auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
    auditpol /set /subcategory:"SAM" /success:disable /failure:disable
    auditpol /set /subcategory:"Certification Services" /success:disable /failure:disable
    auditpol /set /subcategory:"Application Generated" /success:disable /failure:disable
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
    auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
    Write-Host "  - Disabled other Object Access subcategories" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to configure audit policy: $_" -ForegroundColor Red
}

# Function to set SACL on a path with maximum permissions
function Set-AuditRule {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Host "  Path not found: $Path" -ForegroundColor Yellow
        return $false
    }
    
    try {
        $acl = Get-Acl $Path
        
        # Define audit rules for Everyone
        $auditUser = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        
        # Monitor ALL file system rights
        $auditRights = [System.Security.AccessControl.FileSystemRights]::FullControl
        
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                           [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        
        # Remove InheritOnly - audit the folder AND its contents
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        
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
        Write-Host "  ERROR on $Path : $_" -ForegroundColor Red
        return $false
    }
}

# Get all fixed drives
Write-Host "[2/3] Detecting all drives..." -ForegroundColor Green
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Root -match '^[A-Z]:\\$' -and (Test-Path $_.Root)
}

Write-Host "  Found drives: $($drives.Root -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Apply audit to ALL drives at root level - NO PATH FILTERS
Write-Host "[3/3] Applying audit to ALL DRIVES at root level..." -ForegroundColor Red
Write-Host "  NO PATH FILTERS - Monitoring EVERYTHING on every drive" -ForegroundColor Yellow
Write-Host ""
$successCount = 0

foreach ($drive in $drives) {
    Write-Host "  Processing drive: $($drive.Root)" -ForegroundColor Cyan
    if (Set-AuditRule -Path $drive.Root) {
        $successCount++
        Write-Host "  SUCCESS: Audit configured on $($drive.Root) with FullControl monitoring" -ForegroundColor Green
    } else {
        Write-Host "  FAILED: Could not configure audit on $($drive.Root)" -ForegroundColor Red
    }
    Write-Host ""
}

# Verify Audit Policy
Write-Host "Verifying Audit Policy..." -ForegroundColor Green
Write-Host ""
auditpol /get /category:"Object Access"
Write-Host ""

# Summary
Write-Host ""
Write-Host "=== Configuration Complete - NO EXCLUSIONS ===" -ForegroundColor Red
Write-Host "SUCCESS: Configured auditing on $successCount drive(s)" -ForegroundColor Green
Write-Host "SUCCESS: Monitoring ALL files on ALL drives" -ForegroundColor Green
Write-Host "SUCCESS: NO PATH FILTERS applied" -ForegroundColor Red
Write-Host "SUCCESS: NO FILE TYPE FILTERS applied" -ForegroundColor Red
Write-Host "SUCCESS: FullControl audit rights enabled" -ForegroundColor Red
Write-Host "SUCCESS: Monitoring Event ID 4663 only" -ForegroundColor Green
Write-Host ""
Write-Host "Drives monitored:" -ForegroundColor Yellow
foreach ($drive in $drives) {
    Write-Host "  - $($drive.Root) (ALL contents recursively)" -ForegroundColor White
}
Write-Host ""
Write-Host "Audit Events Information:" -ForegroundColor Yellow
Write-Host "  - Event Log: Security" -ForegroundColor White
Write-Host "  - Event ID: 4663 (File System access)" -ForegroundColor White
Write-Host "  - Captures: ALL file system operations" -ForegroundColor White
Write-Host "  - Scope: ENTIRE file system on all drives" -ForegroundColor White
Write-Host ""
Write-Host "To view audit events, run:" -ForegroundColor Yellow
Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 50" -ForegroundColor Cyan
Write-Host ""
Write-Host "CRITICAL WARNINGS:" -ForegroundColor Red
Write-Host "  - This configuration will generate MASSIVE amounts of audit data" -ForegroundColor Yellow
Write-Host "  - Your Security Event Log WILL fill up rapidly" -ForegroundColor Yellow
Write-Host "  - System performance may be significantly impacted" -ForegroundColor Yellow
Write-Host "  - Consider increasing Event Log size to maximum (4GB)" -ForegroundColor Yellow
Write-Host "  - Monitor disk space on system drive closely" -ForegroundColor Yellow
Write-Host "  - This is for COMPREHENSIVE forensic analysis only" -ForegroundColor Yellow
Write-Host ""
