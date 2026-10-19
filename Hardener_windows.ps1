<#
.SYNOPSIS
    Rapid Windows Hardening Script for CCDC with Topology Placeholders
.DESCRIPTION
    Rotates local admin password, safely appends firewall rules for scored ports,
    disables unscored background services, and logs all changes to an audit transcript.
#>

# ==============================================================================
# TOPOLOGY & CONFIGURATION PLACEHOLDERS (FILL ME IN WHEN MAP DROPS)
# ==============================================================================

# 1. SAFETY GATE: Leave this as $false until you have filled in your topology details.
# The script will refuse to run if this is false, preventing accidental default runs.
$TopologyReviewed =$false

# 2. TARGET SERVER IP: Enter the IP address assigned to THIS specific machine.
$TargetServerIP = "[PUT_SERVER_IP_HERE]"         # e.g., "10.1.1.20"

# 3. SCORING ENGINE IPs: Enter the IP address(es) of the official scoring engine.
$ScoringSourceIPs = @(
    # "[PUT_SCORING_ENGINE_IP_HERE]"             # e.g., "10.1.1.50"
)

# 4. SCORED PORTS: Add every TCP/UDP port that your services require to stay up for points.
$ScoredPorts = @(
    [pscustomobject]@{ Protocol = "TCP"; Port = 80 },   # HTTP (Web)
    [pscustomobject]@{ Protocol = "TCP"; Port = 443 },  # HTTPS (Secure Web)
    [pscustomobject]@{ Protocol = "TCP"; Port = 3389 }  # RDP (Remote Management - verify policy)
    # TODO: Add any server-specific scored ports here (e.g., 53 for DNS, 1433 for MSSQL, 3306 for MySQL)
)

# 5. SCORED SERVICES: List any core application services that must NEVER be stopped.
$ScoredServices = @(
    # "<SERVICE_NAME>"                           # e.g., "W3SVC" for IIS, "MSSQLSERVER" for SQL
)

# 6. UNSCORED SERVICES: List vulnerable or unnecessary background services to kill and disable.
$UnscoredServices = @(
    "RemoteRegistry", 
    "WMPNetworkSvc", 
    "SNMP"
    # TODO: Add any other non-scored or vulnerable background services discovered during analysis
)

# 7. OPTIONAL HARDENING TOGGLES: Flip these to $true if your team decides to enforce them.$Options = @{
    RestrictPortsToScoringSources = $false  # Lock inbound traffic strictly to Scoring Engine IPs
    EvictSelectedRdpSessions      = $false  # Log off unauthorized active RDP sessions
    RestartWinRM                  = $false  # Restart WinRM (Keep false if running remotely!)
    EnforceSmbSigning             = $false  # Enforce SMB signing (Verify legacy client compatibility first)
}
# ==============================================================================

# Ensure script is run with administrator privileges
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script must be run with Administrator privileges! Right-click PowerShell and select Run as administrator."
    Exit 1
}

# Enforce Topology Safety Gate Check
if (-not $TopologyReviewed -or $TargetServerIP -match '^<.*>$') {
    throw "[-] ABORT: You must change `$TopologyReviewed to `$true and fill in your `$TargetServerIP before running this script!"
}

# Check for accidental conflicts between scored and unscored service lists
$Conflicts = @($UnscoredServices | Where-Object { $_ -in $ScoredServices })
if ($Conflicts.Count -gt 0) {
    throw "[-] ERROR: A service is listed as both scored and unscored: $($Conflicts -join ', ')"
}

# Validate scoring sources if port restriction is enabled
if ($Options.RestrictPortsToScoringSources -and -not $ScoringSourceIPs.Count) {
    throw "[-] ERROR: Port source restriction is enabled, but no scoring source IPs are listed in `$ScoringSourceIPs."
}

# Validate structure of scored ports
foreach ($Spec in$ScoredPorts) {
    if ($Spec.Protocol -notin @("TCP", "UDP") -or $Spec.Port -notin 1..65535) {
        throw "[-] ERROR: Invalid port entry: $($Spec | Out-String)"
    }
}

# Optional plaintext password for rapid deployment. Leave blank to be prompted securely on screen.
$NewPassword = ""

# ==============================================================================
# EXECUTION & TRANSCRIPT LOGGING
# ==============================================================================
$TranscriptStarted =$false
$LogDirectory = Join-Path$env:ProgramData "CCDC\Logs"
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
$LogPath = Join-Path$LogDirectory "Hardening-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

try {
    try {
        Start-Transcript -Path $LogPath -ErrorAction Stop | Out-Null
        $TranscriptStarted =$true
    }
    catch {
        Write-Warning "[-] Warning: Transcript logging could not start: $_"
    }

    Write-Host "[+] Starting Windows Hardening and Lockdown for server: $TargetServerIP" -ForegroundColor Green

    # STEP 1: Rotate the built-in local Administrator password securely (Targets SID -500)
    if ([string]::IsNullOrWhiteSpace($NewPassword)) {$SecurePassword = Read-Host "Enter new team master password for the local Administrator account" -AsSecureString
    }
    else {
        $SecurePassword = ConvertTo-SecureString$NewPassword -AsPlainText -Force
    }

    $AdminAccounts = @(
        Get-LocalUser -ErrorAction Stop |
            Where-Object { $_.SID.Value -match '-500$' }
    )

    if ($AdminAccounts.Count -ne 1) {
        throw "Expected one built-in local Administrator account; found $($AdminAccounts.Count)."
    }

    Set-LocalUser -Name $AdminAccounts[0].Name -Password$SecurePassword -ErrorAction Stop
    Write-Host "[+] Local Administrator password successfully updated." -ForegroundColor Cyan

    # STEP 2: Enable Windows Firewall & Open Scored Ports Safely
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "[+] Windows Firewall enabled for all network profiles." -ForegroundColor Cyan

    foreach ($Spec in $ScoredPorts) {$RuleName = "CCDC-Allow-$($Spec.Protocol)-$($Spec.Port)"
        if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
            Write-Warning "Rule '$RuleName' already exists. Skipping recreation."
            continue
        }

        $Rule = @{
            DisplayName = $RuleName
            Direction   = "Inbound"
            Protocol    = $Spec.Protocol
            LocalPort   = $Spec.Port
            Action      = "Allow"
            ErrorAction = "Stop"
        }

        if ($Options.RestrictPortsToScoringSources) {
            $Rule.RemoteAddress =$ScoringSourceIPs
        }

        New-NetFirewallRule @Rule
        Write-Host "[+] Allowed inbound traffic on port: $($Spec.Port) ($($Spec.Protocol))" -ForegroundColor Green
    }

    # STEP 3: Disable Risky and Unscored Background Services
    foreach ($Service in$UnscoredServices) {
        if ($Service -ne "[PUT_SERVICE_NAME_HERE]" -and (Get-Service -Name $Service -ErrorAction SilentlyContinue)) {
            Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $Service -StartupType Disabled
            Write-Host "[+] Disabled and stopped unneeded service: $Service" -ForegroundColor Yellow
        }
    }

    # STEP 4: Evict Unauthorized RDP Sessions (Optional Opt-In)
    if ($Options.EvictSelectedRdpSessions) {
        quser.exe
        $RdpSessionIdsToLogoff = @(
            # Type authorized session IDs here if you need to kick intruders out
        )
        $CurrentSessionId = (Get-Process -Id$PID).SessionId

        foreach ($SessionId in$RdpSessionIdsToLogoff) {
            if ($SessionId -eq$CurrentSessionId) {
                Write-Warning "Skipping your current active session ID ($SessionId)."
                continue
            }

            & "$env:SystemRoot\System32\logoff.exe" $SessionId
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to log off RDP session ID $SessionId."
            }
        }
    }

    # STEP 5: Restart WinRM Service (Opt-In Out-of-Band Safeguard)
    if ($Options.RestartWinRM) {
        if ($PSSenderInfo) {
            throw "Refusing to restart WinRM from a remote PowerShell session to prevent self-lockout."
        }
        Restart-Service -Name WinRM -Force -ErrorAction Stop
    }

    # STEP 6: Apply Low-Risk Baseline Hardening (LLMNR & Anonymous Shares)
    Write-Host "[+] Applying low-risk baseline security controls..." -ForegroundColor Cyan
    $DnsClientPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    New-Item -Path $DnsClientPolicy -Force | Out-Null
    New-ItemProperty -Path $DnsClientPolicy -Name EnableMulticast -PropertyType DWord -Value 0 -Force | Out-Null

    $LsaPolicy = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    New-ItemProperty -Path $LsaPolicy -Name RestrictAnonymous -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $LsaPolicy -Name RestrictAnonymousSAM -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $LsaPolicy -Name EveryoneIncludesAnonymous -PropertyType DWord -Value 0 -Force | Out-Null

    # STEP 7: SMB Signing (Optional Opt-In)
    if ($Options.EnforceSmbSigning) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    }

    Write-Host "[+] Windows lockdown completed successfully for $TargetServerIP!" -ForegroundColor Green

}
catch {
    Write-Error "[-] Critical error encountered during script execution: $_"
    throw
}
finally {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "[+] Execution audit transcript log saved securely to: $LogPath" -ForegroundColor Cyan
    }
}