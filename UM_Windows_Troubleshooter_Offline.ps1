<#PSScriptInfo

.VERSION 1.0

.GUID fa3f8397-9d89-4f06-985c-2dfffcfd5520

.AUTHOR Stas Kuvshinov, Swapnil Jain

.COMPANYNAME Microsoft Corporation

.COPYRIGHT © 2018 Microsoft Corporation. All rights reserved.

.TAGS Automation UpdateManagement HybridRunbookWorker Troubleshoot

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Original set of troubleshooting checks for Update Management Agent (Automation Hybrid Runbook Worker) on Windows machines

.PRIVATEDATA

#>

<#

.DESCRIPTION
 Troubleshooting utility for Update Management Agent (Automation Hybrid Runbook Worker) on Windows machines

#>
param(
    [string]$automationAccountLocation,
    [switch]$returnCompactFormat,
    [switch]$returnAsJson
)

$global:validWorkspaceReason = ""
$global:validWorkspaceId = ""

$validationResults = @()
[string]$CurrentResult = ""
[string]$CurrentDetails = ""
function New-RuleCheckResult
{
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$ruleId,
        [string]$ruleName,
        [string]$ruleDescription,
        [string][ValidateSet("Passed","PassedWithWarning", "Failed", "Information")]$result,
        [string]$resultMessage,
        [string]$ruleGroupId = $ruleId,
        [string]$ruleGroupName,
        [string]$resultMessageId = $ruleId,
        [array]$resultMessageArguments = @()
    )

    if ($returnCompactFormat.IsPresent) {
        $compactResult = [pscustomobject] [ordered] @{
            'RuleId'= $ruleId
            'RuleGroupId'= $ruleGroupId
            'CheckResult'= $result
            'CheckResultMessageId'= $resultMessageId
            'CheckResultMessageArguments'= $resultMessageArguments
        }
        return $compactResult
    }

    $fullResult = [pscustomobject] [ordered] @{
        'RuleId'= $ruleId
        'RuleGroupId'= $ruleGroupId
        'RuleName'= $ruleName
        'RuleGroupName' = $ruleGroupName
        'RuleDescription'= $ruleDescription
        'CheckResult'= $result
        'CheckResultMessage'= $resultMessage
        'CheckResultMessageId'= $resultMessageId
        'CheckResultMessageArguments'= $resultMessageArguments
    }
    return $fullResult
}

function checkRegValue
{
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$path,
        [string][Parameter(Mandatory=$true)]$name,
        [int][Parameter(Mandatory=$true)]$valueToCheck
    )

    $val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
    if($val.$name -eq $null) {
        return $null
    }

    if($val.$name -eq $valueToCheck) {
        return $true
    } else {
        return $false
    }
}

function getRegValue {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory = $true)]$path,
        [string][Parameter(Mandatory = $true)]$name
    )

    $val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
    if ($val.$name -eq $null) {
        return $null
    }
    return $val.$name
}

function Validate-OperatingSystem {
    $osRequirementsLink = "https://docs.microsoft.com/en-Us/azure/automation/update-management/operating-system-requirements"

    $ruleId = "OperatingSystemCheck"
    $ruleName = "Operating System"
    $ruleDescription = "The Windows Operating system must be version 6.1.7600 (Windows Server 2008 R2) or higher"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisite Checks"
    $resultMessageArguments = @()

    if([System.Environment]::OSVersion.Version -ge [System.Version]"6.1.7600") {
        $result = "Passed"
        $resultMessage = "Operating System version is supported"
    } else {
        $result = "Failed"
        $resultMessage = "Operating System version is not supported. Supported versions listed here: $osRequirementsLink"
        $resultMessageArguments += $osRequirementsLink
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-NetFrameworkInstalled {
    $netFrameworkDownloadLink = "https://www.microsoft.com/net/download/dotnet-framework-runtime"

    $ruleId = "DotNetFrameworkInstalledCheck"
    $ruleName = ".Net Framework 4.6.2+"
    $ruleDescription = ".NET Framework version 4.6.2 or higher is required"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisite Checks"
    $resultMessageArguments = @()

    # https://docs.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
    $dotNetFullRegistryPath = "HKLM:SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"
    if((Get-ChildItem $dotNetFullRegistryPath -ErrorAction SilentlyContinue) -ne $null) {
        $versionCheck = (Get-ChildItem $dotNetFullRegistryPath) | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 394802 }
        if($versionCheck -eq $true) {
            $result = "Passed"
            $resultMessage = ".NET Framework version 4.6.2+ is found"
        } else {
            $result = "Failed"
            $resultMessage = ".NET Framework version 4.6.2 or higher is required: $netFrameworkDownloadLink"
            $resultMessageArguments += $netFrameworkDownloadLink
        }
    } else{
        $result = "Failed"
        $resultMessage = ".NET Framework version 4.6.2 or higher is required: $netFrameworkDownloadLink"
        $resultMessageArguments += $netFrameworkDownloadLink
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-WmfInstalled {
    $wmfDownloadLink = "https://www.microsoft.com/download/details.aspx?id=54616"
    $ruleId = "WindowsManagementFrameworkInstalledCheck"
    $ruleName = "WMF 5.1"
    $ruleDescription = "Windows Management Framework version 4.0 or higher is required (version 5.1 or higher is preferable)"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisite Checks"

    $psVersion = $PSVersionTable.PSVersion
    $resultMessageArguments = @() + $psVersion

    if($psVersion -ge 5.1) {
        $result = "Passed"
        $resultMessage = "Detected Windows Management Framework version: $psVersion"
    } elseif($psVersion.Major -ge 4) {
        $result = "PassedWithWarning"
        $resultMessage = "Detected Windows Management Framework version: $psVersion. Consider upgrading to version 5.1 or higher for increased reliability: $wmfDownloadLink"
        $resultMessageArguments += $wmfDownloadLink
    } else {
        $result = "Failed"
        $resultMessage = "Detected Windows Management Framework version: $psVersion. Version 4.0 or higher is required (version 5.1 or higher is preferable): $wmfDownloadLink"
        $resultMessageArguments += $wmfDownloadLink
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-TlsEnabled {
    $ruleId = "TlsVersionCheck"
    $ruleName = "TLS 1.2"
    $ruleDescription = "Client and Server connections must support TLS 1.2"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisite Checks"

    $tls12RegistryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\"
    $serverEnabled =     checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 1
    $ServerNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 0
    $clientEnabled =     checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 1
    $ClientNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 0

    $ServerNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 0
    $ServerDisabled =   checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 1
    $ClientNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 0
    $ClientDisabled =   checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 1

    if ($validationResults[0].CheckResult -ne "Passed" -and [System.Environment]::OSVersion.Version -ge [System.Version]"6.0.6001") {
        $result = "Failed"
        $resultMessageId = "$ruleId.$result"
        $resultMessage = "TLS 1.2 is not enabled by default on the Operating System. Follow the instructions to enable it: https://support.microsoft.com/help/4019276/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows"
    } elseif([System.Environment]::OSVersion.Version -ge [System.Version]"6.1.7601" -and [System.Environment]::OSVersion.Version -le [System.Version]"6.1.8400") {
        if($ClientNotDisabled -and $ServerNotDisabled -and !($ServerNotEnabled -and $ClientNotEnabled)) {
            $result = "Passed"
            $resultMessage = "TLS 1.2 is enabled on the Operating System."
            $resultMessageId = "$ruleId.$result"
        } else {
            $result = "Failed"
            $reason = "NotExplicitlyEnabled"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "TLS 1.2 is not enabled by default on the Operating System. Follow the instructions to enable it: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12"
        }
    } elseif([System.Environment]::OSVersion.Version -ge [System.Version]"6.2.9200") {
        if($ClientDisabled -or $ServerDisabled -or $ServerNotEnabled -or $ClientNotEnabled) {
            $result = "Failed"
            $reason = "ExplicitlyDisabled"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "TLS 1.2 is supported by the Operating System, but currently disabled. Follow the instructions to re-enable: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12"
        } else {
            $result = "Passed"
            $reason = "EnabledByDefault"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "TLS 1.2 is enabled by default on the Operating System."
        }
    } else {
        $result = "Failed"
        $reason = "NoDefaultSupport"
        $resultMessageId = "$ruleId.$result.$reason"
        $resultMessage = "Your OS does not support TLS 1.2 by default."
    }

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId
}

function Validate-EndpointConnectivity {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$endpoint,
        [string][Parameter(Mandatory=$true)]$ruleId,
        [string][Parameter(Mandatory=$true)]$ruleName,
        [string]$ruleDescription = "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with $endpoint"
    )

    $result = $null
    $resultMessage = $null
    $ruleGroupId = "connectivity"
    $ruleGroupName = "connectivity"
    $resultMessageArguments = @() + $endpoint

    try {
        if((Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded) {
            $result = "Passed"
            $resultMessage = "TCP Test for $endpoint (port 443) succeeded"
        } else {
            $result = "Failed"
            $resultMessage = "TCP Test for $endpoint (port 443) failed"
        }
    }
    catch {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $client.Connect($endpoint, 443)
            $result = "Passed"
            $resultMessage = "TCP Test for $endpoint (port 443) succeeded"
        } catch {
            $result = "Failed"
            $resultMessage = "TCP Test for $endpoint (port 443) failed"
        } finally {
            $client.Dispose()
        }
    }

    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-RegistrationEndpointsConnectivity {
    $validationResults = @()

    $workspaceReason = Get-ValidWorkspace

    if($workspaceReason -eq "Multiple" -or $workspaceReason -eq "None") {
        $ruleId = "AutomationAgentServiceConnectivityCheck1"
        $ruleName = "Registration endpoint"

        $result = "Failed"
        $reason = "NoRegistrationFound"
        $resultMessage = "Unable to find Workspace registration information"
        $ruleGroupId = "connectivity"
        $ruleGroupName = "connectivity"
        $resultMessageId = "$ruleId.$result.$reason"

        return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
    }

    $workspace = $global:validWorkspaceId

    if($automationAccountLocation -eq "usgovvirginia" -or $automationAccountLocation -eq "usgovarizona"){
        $endpoint = "$workspace.agentsvc.azure-automation.us"
    } elseif($automationAccountLocation -eq "chinaeast2") {
        $endpoint = "$workspace.agentsvc.azure-automation.cn"
    } else {
        $endpoint = "$workspace.agentsvc.azure-automation.net"
    }
    $ruleId = "AutomationAgentServiceConnectivityCheck1"
    $ruleName = "Registration endpoint"

    $validationResults += Validate-EndpointConnectivity $endpoint $ruleId $ruleName
    return $validationResults
}

function Validate-OperationsEndpointConnectivity {
    # https://docs.microsoft.com/azure/automation/automation-hybrid-runbook-worker#hybrid-worker-role
    if($automationAccountLocation -eq "usgovvirginia"){
        $endpoint = "usge-jobruntimedata-prod-su1.azure-automation.us"
    } elseif($automationAccountLocation -eq "usgovarizona") {
        $endpoint = "phx-jobruntimedata-prod-su1.azure-automation.us"
    } elseif($automationAccountLocation -eq "chinaeast2") {
        $endpoint = "sha2-jobruntimedata-prod-su1.azure-automation.cn"
    } else {
        $jrdsEndpointLocationMoniker = switch ( $automationAccountLocation ) {
            "australiasoutheast"{ "ase"  }
            "canadacentral"     { "cc"   }
            "centralindia"      { "cid"  }
            "eastus2"           { "eus2" }
            "japaneast"         { "jpe"  }
            "northeurope"       { "ne"   }
            "southcentralus"    { "scus" }
            "southeastasia"     { "sea"  }
            "uksouth"           { "uks"  }
            "westcentralus"     { "wcus" }
            "westeurope"        { "we"   }
            "westus2"           { "wus2" }

            default             { "eus2" }
        }
        $endpoint = "$jrdsEndpointLocationMoniker-jobruntimedata-prod-su1.azure-automation.net"
    }
    $ruleId = "AutomationJobRuntimeDataServiceConnectivityCheck"
    $ruleName = "Operations endpoint"

    return Validate-EndpointConnectivity $endpoint $ruleId $ruleName
}

function Validate-LAOdsEndpointConnectivity {
    #https://docs.microsoft.com/en-us/azure/automation/automation-network-configuration#update-management-and-change-tracking-and-inventory
    $odsEndpoint = ""
    $ruleId = "LAOdsEndpointConnectivity"
    $ruleName = "LA ODS endpoint"
    $ruleDescription = "Proxy and firewall configuration must allow to communicate with LA ODS endpoint"

    $workspaceReason = Get-ValidWorkspace

    if($workspaceReason -eq "None") {
        $ruleGroupId = "connectivity"
        $ruleGroupName = "connectivity"
        $result = "Failed"
        $reason = "NoRegistrationFound"
        $resultMessage = "Unable to find Workspace registration information"
        $resultMessageId = "$ruleId.$result"
        return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
    }

    if($workspaceReason -eq "Multiple") {
        $ruleGroupId = "connectivity"
        $ruleGroupName = "connectivity"
        $result = "Failed"
        $reason = "MultipleWorkspaces"
        $resultMessage = "VM connected to multiple workspaces."
        $resultMessageId = "$ruleId.$result"
        return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
    }

    $workspace = $global:validWorkspaceId

    if($automationAccountLocation -eq "usgovvirginia"){
        $odsEndpoint = "$workspace.ods.opinsights.azure.us"
    } elseif($automationAccountLocation -eq "chinaeast2") {
        $odsEndpoint = "$workspace.ods.opinsights.azure.cn"
    } else {
        $odsEndpoint = "$workspace.ods.opinsights.azure.com"
    }

    return Validate-EndpointConnectivity $odsEndpoint $ruleId $ruleName $ruleDescription
}

function Get-ValidWorkspace {
    if($global:validWorkspaceReason -ne "") {
        return $global:validWorkspaceReason
    }

    $wsFromAgentCmd = @{}
    $totalWorkspacePresent = 0
    try {
        $workspaceInfo = (New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg').GetCloudWorkspaces()
        foreach ($workspace in $workspaceInfo) {
            $laWorkspaceId = $workspace.workspaceID.ToString()
            $wsFromAgentCmd[$laWorkspaceId] = 1
            
            $totalWorkspacePresent += 1
        }
    } catch { #pass
    }

    try {
        $mmaChannel = "Operations Manager"
        $eventId = 1210
        $workspaces = Get-WinEvent $mmaChannel | Where-Object { ($_.Id -eq $eventId) -and ($_.Message.IndexOf("updates;")) -ne -1 } | Select-Object -Property {$_.Message.Substring($_.Message.IndexOf("AOI-")+4, 36)} -Unique

        $cnt = 0
        Foreach ($w in $workspaces)
        {
            $w = $w.'$_.Message.Substring($_.Message.IndexOf("AOI-")+4, 36)'

            if($wsFromAgentCmd[$w] -eq 1) {
                $cnt += 1
                $global:validWorkspaceId = $w
            }
        }

        if ($cnt -eq 1) {
            if($totalWorkspacePresent -gt 1) {
                $global:validWorkspaceReason = "MultipleButValid"
            }
            return $global:validWorkspaceReason #Only one valid workspace found.
        } elseif($cnt -gt 1) {
            $global:validWorkspaceReason = "Multiple"
            $global:validWorkspaceId = ""
            #VM connected to multiple workspaces
        } else {
            $global:validWorkspaceReason = "None"
            #Event id exists, but no workspace found with updates' solution.
        }
    } catch {
        $global:validWorkspaceReason = "None" #No such eventId or event channel exist
    }

    return $global:validWorkspaceReason
}

function Validate-LAOmsEndpointConnectivity {
    #https://docs.microsoft.com/en-us/azure/automation/automation-network-configuration#update-management-and-change-tracking-and-inventory
    $omsEndpoint = ""

    $ruleId = "LAOmsEndpointConnectivity"
    $ruleName = "LA OMS endpoint"
    $ruleDescription = "Proxy and firewall configuration must allow to communicate with LA OMS endpoint"

    $workspaceReason = Get-ValidWorkspace

    if($workspaceReason -eq "None") {
        $ruleGroupId = "connectivity"
        $ruleGroupName = "connectivity"
        $result = "Failed"
        $reason = "NoRegistrationFound"
        $resultMessage = "Unable to find Workspace registration information"
        $resultMessageId = "$ruleId.$result"
        return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
    }

    if($workspaceReason -eq "Multiple") {
        $ruleGroupId = "connectivity"
        $ruleGroupName = "connectivity"
        $result = "Failed"
        $reason = "MultipleWorkspaces"
        $resultMessage = "VM connected to multiple workspaces."
        $resultMessageId = "$ruleId.$result"
        return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
    }

    $workspace = $global:validWorkspaceId

    if($automationAccountLocation -eq "usgovvirginia"){
        $omsEndpoint = "$workspace.oms.opinsights.azure.us"
    } elseif($automationAccountLocation -eq "chinaeast2") {
        $omsEndpoint = "$workspace.oms.opinsights.azure.cn"
    } else {
        $omsEndpoint = "$workspace.oms.opinsights.azure.com"
    }

    return Validate-EndpointConnectivity $omsEndpoint $ruleId $ruleName $ruleDescription
}

function Validate-MmaIsRunning {
    $mmaServiceName = "HealthService"
    $mmaServiceDisplayName = "Microsoft Monitoring Agent"

    $ruleId = "MonitoringAgentServiceRunningCheck"
    $ruleName = "Monitoring Agent service status"
    $ruleDescription = "$mmaServiceName must be running on the machine"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "servicehealth"
    $ruleGroupName = "VM Service Health Checks"
    $resultMessageArguments = @() + $mmaServiceDisplayName + $mmaServiceName

    if(Get-Service -Name $mmaServiceName -ErrorAction SilentlyContinue| Where-Object {$_.Status -eq "Running"} | Select-Object) {
        $result = "Passed"
        $resultMessage = "$mmaServiceDisplayName service ($mmaServiceName) is running"
    } else {
        $result = "Failed"
        $resultMessage = "$mmaServiceDisplayName service ($mmaServiceName) is not running"
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-MmaEventLogHasNoErrors {
    $mmaServiceName = "Microsoft Monitoring Agent"
    $logName = "Operations Manager"
    $eventId = 4502

    $ruleId = "MonitoringAgentServiceEventsCheck"
    $ruleName = "Monitoring Agent service events"
    $ruleDescription = "Event Log must not have event 4502 logged in the past 24 hours"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "servicehealth"
    $ruleGroupName = "VM Service Health Checks"
    $resultMessageArguments = @() + $mmaServiceName + $logName + $eventId

    $OpsMgrLogExists = [System.Diagnostics.EventLog]::Exists($logName);
    if($OpsMgrLogExists) {
        $event = Get-EventLog -LogName "Operations Manager" -Source "Health Service Modules" -After (Get-Date).AddHours(-24) | where {$_.eventID -eq $eventId}
        if($event -eq $null) {
            $result = "Passed"
            $resultMessageId = "$ruleId.$result"
            $resultMessage = "$mmaServiceName service Event Log ($logName) does not have event $eventId logged in the last 24 hours."
        } else {
            $result = "Failed"
            $reason = "EventFound"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "$mmaServiceName service Event Log ($logName) has event $eventId logged in the last 24 hours. Look at the results of other checks to troubleshoot the reasons."
        }
    } else {
        $result = "Failed"
        $reason = "NoLog"
        $resultMessageId = "$ruleId.$result.$reason"
        $resultMessage = "$mmaServiceName service Event Log ($logName) does not exist on the machine"
    }

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-MMALinkedWorkspace {
    $ruleId = "LinkedWorkspaceCheck"
    $ruleName = "VM's Linked Workspace"
    $ruleDescription = "Get linked workspace info of the VM"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "servicehealth"
    $ruleGroupName = "VM Service Health Checks"
    
    $workspaceReason = Get-ValidWorkspace
    $workspace = $global:validWorkspaceId

    $resultMessageArguments = @() + $workspace

    if ("None".equals($workspaceReason)) {
        $result = "Failed"
        $resultMessage = "VM is not reporting to any workspace."
        $reason = "NoWorkspace"
        $resultMessageId = "$ruleId.$result.$reason"
    }
    else {
        if ("MultipleButValid".equals($workspaceReason)) {
            $result = "PassedWithWarning"
            $resultMessage = "Although VM is reporting to multiple workspaces, the updates solution is configured in only one workspace: $workspace. Please make sure automation account is linked to same workspace."
        } elseif ("Multiple".equals($workspaceReason)) {
            $result = "Failed"
            $resultMessage = "VM is reporting to multiple workspaces with updates solution configured. Please make sure that only one workspace has updates solution and automation account is linked to that workspace."
        } else {
            $result = "Passed"
            $resultMessage = "VM is reporting to workspace $workspace. Please make sure automation account is linked to same workspace."
        }
        $resultMessageId = "$ruleId.$result"
    }
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-MachineKeysFolderAccess {
    $folder = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys"

    $ruleId = "CryptoRsaMachineKeysFolderAccessCheck"
    $ruleName = "Crypto RSA MachineKeys Folder Access"
    $ruleDescription = "SYSTEM account must have WRITE and MODIFY access to '$folder'"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "permissions"
    $ruleGroupName = "Access Permission Checks"
    $resultMessageArguments = @() + $folder

    $User = $env:UserName
    $permission = (Get-Acl $folder).Access | ? {($_.IdentityReference -match $User) -or ($_.IdentityReference -match "Everyone")} | Select IdentityReference, FileSystemRights
    if ($permission) {
        $result = "Passed"
        $resultMessage = "Have permissions to access $folder"
    } else {
        $result = "Failed"
        $resultMessage = "Missing permissions to access $folder"
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-AlwaysAutoRebootEnabled {
    $ruleId = "AlwaysAutoRebootCheck"
    $ruleName = "AutoReboot"
    $ruleDescription = "Automatic reboot should not be enable as it forces a reboot irrespective of update configuration"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "machineSettings"
    $ruleGroupName = "Machine Override Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    $rebootEnabledBySchedule = checkRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTime" 1
    $rebootEnabledByDuration = getRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTimeMinutes"


    if (  $rebootEnabledBySchedule -or $rebootEnabledByDuration ) {
        $result = "PassedWithWarning"
        $reason = "Auto Reboot is enabled on the system and will interfere with Update Management Configuration passed during runs"
        $resultMessage = "Windows Update reboot registry keys are set. This can cause unexpected reboots when installing updates"
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Update reboot registry keys are not set to automatically reboot"

    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-AutomaticUpdateEnabled {
    $ruleId = "AutomaticUpdateCheck"
    $ruleName = "AutoUpdate"
    $ruleDescription = "AutoUpdate should not be enabled on the machine"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "machineSettings"
    $ruleGroupName = "Machine Override Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    $autoUpdateEnabled = checkRegValue ($automaticUpdatePath) "AUOptions" 4


    if ( $autoUpdateEnabled ) {
        $result = "PassedWithWarning"
        $reason = "Auto Update is enabled on the machine and will interfere with Update management Solution"
        $resultMessage = "Windows Update will automatically download and install new updates as they become available"
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Update is not set to automatically install updates as they become available"

    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-WSUSServerConfigured {
    $ruleId = "WSUSServerConfigured"
    $ruleName = "isWSUSServerConfigured"
    $ruleDescription = "Increase awareness on WSUS configured on the server"
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "machineSettings"
    $ruleGroupName = "Machine Override Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
    $wsusServerConfigured = getRegValue ($automaticUpdatePath) "WUServer"

    if ( $null -ne $wsusServerConfigured ) {
        $result = "PassedWithWarning"
        $reason = "WSUS Server is configured on the server"
        $resultMessage = "Windows Updates are downloading from a configured WSUS Server $wsusServerConfigured. Ensure the WSUS server is accessible and updates are being approved for installation"
        $resultMessageArguments = @() + $wsusServerConfigured
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Updates are downloading from the default Windows Update location. Ensure the server has access to the Windows Update service"
    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-HttpsConnection {
    $ruleId = "HttpsConnection"
    $ruleName = "Https connection"
    $ruleDescription = "Check if VM is able to make https requests."
    $result = $null
    $resultMessage = ""
    $ruleGroupId = "connectivity"
    $ruleGroupName = "connectivity"
    $resultMessageId = ""
    $resultMessageArguments = @()

    $uri = "https://eus2-jobruntimedata-prod-su1.azure-automation.net"
    try
    {
        Invoke-WebRequest -URI $uri -UseBasicParsing > $null
        $result = "Passed"
        $resultMessage = "VM is able to make https requests."
        $resultMessageId = "$ruleId.$result"
    }
    catch
    {
        if ($_ -match "Forbidden")
        {
            $result = "Passed"
            $resultMessage = "VM is able to make https requests."
            $resultMessageId = "$ruleId.$result"
        }
        else
        {
            $request = [System.Net.WebRequest]::Create($uri)
            $request.Proxy = [System.Net.WebProxy]::new()
            $response = $null
            try
            {
                $response = $request.GetResponse()
                if ($response.StatusCode -eq 200)
                {
                    $result = "PassedWithWarning"
                    $resultMessage = "Please check if the proxy server is configured properly to allow https requests."
                }
                else
                {
                    $result = "Failed"
                    $resultMessage = "VM is not able to make https requests. Please check your network connection. Unable to reach $uri."
                    $resultMessageArguments += $uri
                }

                $resultMessageId = "$ruleId.$result"
            }
            catch
            {
                if ($_ -match "Forbidden")
                {
                    $result = "PassedWithWarning"
                    $resultMessage = "Please check if the proxy server is configured properly to allow https requests."
                }

                if ($_ -match "Unable to connect to the remote server" -or
                    $_ -match "The underlying connection was closed")
                {
                    $result = "Failed"
                    $resultMessage = "VM is not able to make https requests. Please check your network connection. Unable to reach $uri."
                    $resultMessageArguments += $uri
                }

                $resultMessageId = "$ruleId.$result"
            }
            finally
            {
                if ($response -ne $null)
                {
                    $response.Dispose()
                }
            }
        }
    }

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-ProxySettings {
    $ruleId = "ProxySettings"
    $ruleName = "Proxy settings"
    $ruleDescription = "Check if Proxy is enabled on the VM."
    $result = $null
    $resultMessage = ""
    $ruleGroupId = "connectivity"
    $ruleGroupName = "connectivity"
    $resultMessageId = ""
    $resultMessageArguments = @()

    $res = netsh winhttp show proxy
    if ($res -like '*Direct access*') {
        $result = "Passed"
        $resultMessage = "Proxy is not set."
    } else {
        $result = "PassedWithWarning"
        $resultMessage = "Proxy is set."
    }

    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-IMDSConnectivity
{
    $ruleId = "IMDSConnectivity"
    $ruleName = "IMDS endpoint connectivity"
    $ruleDescription = "Check if VM is able to reach IMDS server to get VM information."
    $result = $null
    $resultMessage = ""
    $ruleGroupId = "connectivity"
    $ruleGroupName = "connectivity"
    $resultMessageId = ""
    $resultMessageArguments = @()

    try {
        $response = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2018-02-01"
        $result = "Passed"
        $resultMessage = "VM is able to reach IMDS server"
        $resultMessageId = "$ruleId.$result"
    } catch {
        try {
            $request = [System.Net.WebRequest]::Create("http://169.254.169.254/metadata/instance?api-version=2018-02-01")
            $request.Proxy = [System.Net.WebProxy]::new()
            $request.Headers.Add("Metadata","True")
            $resultMessage = $request.GetResponse()
            $result = "Failed"
            $resultMessage = "VM is likely behind a proxy and UM may not be able to query IMDS to get VM info."
            $resultMessageId = "$ruleId.$result"
        }
        catch {
            $result = "PassedWithWarning"
            $resultMessage = "VM is not able to reach IMDS server. Consider this as a Failure if this is an Azure VM."
            $resultMessageId = "$ruleId.$result"
        }
    }

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-SHRWIsRunning {
    $mmaServiceName = "HealthService"
    $mmaServiceDisplayName = "Microsoft Monitoring Agent"
    # Update the event id for HRW start and stop here in case it is updated.
    $hrwStartedEvent = 15003
    $hrwStoppedEvent = 15004
    $mmaEventChannel = "Microsoft-SMA/Operational"

    $ruleId = "SystemHybridRunbookWorkerRunningCheck"
    $ruleName = "Hybrid runbook worker status"
    $ruleDescription = "Hybrid runbook worker must be in running state."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "servicehealth"
    $ruleGroupName = "VM Service Health Checks"

    $event = Get-WinEvent $mmaEventChannel | Where-Object { ($_.Id -eq $hrwStartedEvent -or $_.Id -eq $hrwStoppedEvent) -and($_.Properties[1].Value -eq $_.Properties[2].Value + "_" + $_.Properties[3].Value) } | Select-Object -First 1
    if ($event.Id -eq $hrwStartedEvent)
    {
        $result = "Passed"
        $resultMessageArguments = @()
        $resultMessage = "Hybrid runbook worker is running."
    }
    else
    {
	    $result = "Failed"
        $resultMessageArguments = @() + $mmaServiceDisplayName + $mmaServiceName
        $resultMessage = "Hybrid runbook worker is in stopped state. Please restart $mmaServiceDisplayName service ($mmaServiceName) and rerun the troubleshooter to ensure that hybrid runbook worker is in running state."
    }

    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-WUIsEnabled {
    $windowsServiceName = "wuauserv"
    $windowsServiceDisplayName = "Windows Update"

    $ruleId = "WUServiceRunningCheck"
    $ruleName = "WU service status"
    $ruleDescription = "WU must not be in the disabled state."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "servicehealth"
    $ruleGroupName = "WU Service Health Check"
    $resultMessageArguments = @() + $windowsServiceDisplayName + $windowsServiceName

    if(Get-Service -Name $windowsServiceName -ErrorAction SilentlyContinue | select -property name,starttype | Where-Object {$_.StartType -eq "Disabled"} | Select-Object) {
        $result = "Failed"
        $resultMessage = "$windowsServiceDisplayName service ($windowsServiceName) is disabled. Please set it to automatic or manual. You can run 'sc config wuauserv start= demand' to set it to manual."
    } else {
        $result = "Passed"
        $resultMessage = "$windowsServiceDisplayName service ($windowsServiceName) is running."
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

$validationResults += Validate-OperatingSystem
$validationResults += Validate-NetFrameworkInstalled
$validationResults += Validate-WmfInstalled
Validate-RegistrationEndpointsConnectivity | % { $validationResults += $_ }
$validationResults += Validate-OperationsEndpointConnectivity
$validationResults += Validate-MmaIsRunning
$validationResults += Validate-SHRWIsRunning
$validationResults += Validate-MmaEventLogHasNoErrors
$validationResults += Validate-MMALinkedWorkspace
$validationResults += Validate-MachineKeysFolderAccess
$validationResults += Validate-TlsEnabled
$validationResults += Validate-AlwaysAutoRebootEnabled
$validationResults += Validate-WSUSServerConfigured
$validationResults += Validate-AutomaticUpdateEnabled
$validationResults += Validate-HttpsConnection
$validationResults += Validate-ProxySettings
$validationResults += Validate-IMDSConnectivity
$validationResults += Validate-WUIsEnabled
$validationResults += Validate-LAOdsEndpointConnectivity
$validationResults += Validate-LAOmsEndpointConnectivity

if($returnAsJson.IsPresent) {
    return ConvertTo-Json $validationResults -Compress
} else {
    return $validationResults
}
