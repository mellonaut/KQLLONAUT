# https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/Defender%20For%20Endpoint

Connect-AzAccount
$sub = Get-azsubscription
Set-AzContext -Subscription $sub
$workspaceName = "sc200"
$workspaceRG = "sc-200"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Devies with most SMB Sessions
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