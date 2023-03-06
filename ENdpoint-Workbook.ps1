# https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/Defender%20For%20Endpoint

Connect-AzAccount
$sub = Get-azsubscription
Set-AzContext -Subscription $sub
$workspaceName = "sc200"
$workspaceRG = "sc-200"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Device events by IP
$deviceByIP = 'DeviceNetworkEvents 
| where RemoteIP == "52.176.49.76"'
$deviceByIP = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $deviceByIP
$deviceByIP.Results

# File Creation in last hour
$deviceFileEvents = 'DeviceFileEvents 
| where Timestamp > ago(1h) 
| project FileName, FolderPath, SHA1, DeviceName, Timestamp 
| limit 1000'
$deviceFileEvents = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $deviceFileEvents
$deviceFileEvents.Results

# List Devices access bad URL
$deviceBadUrl = 'DeviceNetworkEvents 
| where RemoteUrl == "azureedge.net" 
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine '
$deviceBadUrl = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $deviceBadUrl 
$deviceBadUrl.Results

# Specific device
$deviceBadUrl2 = 'DeviceNetworkEvents 
| where RemoteUrl == "azureedge.net" and DeviceName contains "shrine" 
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine '
$deviceBadUrl2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $deviceBadUrl2 
$deviceBadUrl2.Results

# Base64 encode command run
"DeviceProcessEvents 
| where Timestamp > ago(14d) 
| where ProcessCommandLine contains ".decode('base64')" or ProcessCommandLine contains "base64 --decode" or ProcessCommandLine contains ".decode64(" 
| project Timestamp , DeviceName , FileName , FolderPath , ProcessCommandLine , InitiatingProcessCommandLine  
| top 100 by Timestamp" 

# Devices with most SMB Sessions
$mdeQuery =  'let TimeFrame = 30d; 
let AllDomainControllers =
     DeviceNetworkEvents
     | where LocalPort == 88
     | where LocalIPType == "FourToSixMapping"
     | summarize make_set(DeviceId);
DeviceNetworkEvents
| where Timestamp < ago(TimeFrame)
| where RemotePort == 445
| where not(DeviceId in (AllDomainControllers))
| summarize TotalRemoteConnections = dcount(RemoteIP) by DeviceName
| sort by TotalRemoteConnections'
$mdeQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery
$mdeQuery.Results

$sentinelQuery = 'let TimeFrame = 30d; 
let AllDomainControllers =
     DeviceNetworkEvents
     | where LocalPort == 88
     | where LocalIPType == "FourToSixMapping"
     | summarize make_set(DeviceId);
DeviceNetworkEvents
| where Timestamp < ago(TimeFrame)
| where RemotePort == 445
| where not(DeviceId in (AllDomainControllers))
| summarize TotalRemoteConnections = dcount(RemoteIP) by DeviceName
| sort by TotalRemoteConnections'
$sentinelQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery
$sentinelQuery.Results

# Look for public IP addresses that failed to logon to a computer multiple times, using multiple accounts, and eventually succeeded.
$mdeQuery3a = 'DeviceLogonEvents
| where isnotempty(RemoteIP) 
    and AccountName !endswith "$"
    and RemoteIPType == "Public"
| extend Account=strcat(AccountDomain, "\\", AccountName)
| summarize 
    Successful=countif(ActionType == "LogonSuccess"),
    Failed = countif(ActionType == "LogonFailed"),
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"),
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"),
    FailedAccounts = makeset(iff(ActionType == "LogonFailed", Account, ""), 5),
    SuccessfulAccounts = makeset(iff(ActionType == "LogonSuccess", Account, ""), 5)
    by DeviceName, RemoteIP, RemoteIPType
| where Failed > 10 and Successful > 0 and FailedAccountsCount > 2 and SuccessfulAccountsCount == 1'
$mdeQuery3a = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery3a
$mdeQuery3a.Results

$mdeQuery3b = 'DeviceLogonEvents 
| where isnotempty(RemoteIP)  
    and AccountName !endswith "$" 
    and RemoteIPType == "Public" 
| extend Account=strcat(AccountDomain, "\\", AccountName) 
| summarize  
    Successful=countif(ActionType == "LogonSuccess"), 
    Failed = countif(ActionType == "LogonFailed"), 
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"), 
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"), 
    FailedAccounts = makeset(iff(ActionType == "LogonFailed", Account, ""), 5), 
    SuccessfulAccounts = makeset(iff(ActionType == "LogonSuccess", Account, ""), 5) 
    by DeviceName, RemoteIP, RemoteIPType 
| where Failed > 10 and Successful > 0 and FailedAccountsCount > 2 and SuccessfulAccountsCount == 1'
$mdeQuery3b = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery3b
$mdeQuery3b.Results


$mdeQuery3 = 'DeviceLogonEvents
| where isnotempty(RemoteDeviceName)
| extend Account=strcat(AccountDomain, "\\", AccountName)
| summarize 
    Successful=countif(ActionType == "LogonSuccess"),
    Failed = countif(ActionType == "LogonFailed"),
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"),
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"),
    FailedComputerCount = dcountif(DeviceName, ActionType == "LogonFailed"),
    SuccessfulComputerCount = dcountif(DeviceName, ActionType == "LogonSuccess")
    by RemoteDeviceName
| where
    Successful > 0 and
    ((FailedComputerCount > 100 and FailedComputerCount > SuccessfulComputerCount) or
        (FailedAccountsCount > 100 and FailedAccountsCount > SuccessfulAccountsCount))'
$mdeQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery3
$mdeQuery3.Results

# Machines failing to log-on to multiple machines or multiple accounts
$machineLogonQuery = 'DeviceLogonEvents 
| where isnotempty(RemoteDeviceName) 
| extend Account=strcat(AccountDomain, "\\", AccountName) 
| summarize  
    Successful=countif(ActionType == "LogonSuccess"), 
    Failed = countif(ActionType == "LogonFailed"), 
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"), 
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"), 
    FailedComputerCount = dcountif(DeviceName, ActionType == "LogonFailed"), 
    SuccessfulComputerCount = dcountif(DeviceName, ActionType == "LogonSuccess") 
    by RemoteDeviceName 
| where 
    Successful > 0 and 
    ((FailedComputerCount > 100 and FailedComputerCount > SuccessfulComputerCount) or 
        (FailedAccountsCount > 100 and FailedAccountsCount > SuccessfulAccountsCount)'
        $machineLogonQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $machineLogonQuery 
        $machineLogonQuery.Results
