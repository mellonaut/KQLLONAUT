Connect-AzAccount
$sub = Get-azsubscription
Set-AzContext -Subscription $sub
$workspaceName = "sc200"
$workspaceRG = "sc-200"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Account set to have Password Never Expires

$mdiQuery = 'IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.["FROM Account Password Never Expires"]
| extend NewValue = AdditionalInfo.["TO Account Password Never Expires"]
| where NewValue == true
| project
     Timestamp,
     AccountName,
     AccountDomain,
     OriginalValue,
     NewValue,
     ReportId,
     DeviceName'
$mdiQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdiQuery
$mdiQuery.Results

$sentinelQuery1 = 'IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.["FROM Account Password Never Expires"]
| extend NewValue = AdditionalInfo.["TO Account Password Never Expires"]
| where NewValue == true
| project
     TimeGenerated,
     AccountName,
     AccountDomain,
     OriginalValue,
     NewValue,
     ReportId,
     DeviceName'
$sentinelQuery1 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery1
$sentinelQuery1.Results

# Look for bloodhound like enumeration

$mdiQuery1 = "IdentityDirectoryEvents
| where ActionType == 'Potential lateral movement path identified'
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT']
| extend FromAccount = AdditionalFields.['FROM.ACCOUNT']
| project
     Timestamp,
     LateralMovementPathToSensitiveAccount,
     FromAccount,
     DeviceName,
     AccountName,
     AccountDomain'"
$mdiQuery1 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdiQuery1
$mdiQuery1.Results

$sentinelQuery2 = "IdentityDirectoryEvents
| where ActionType == 'Potential lateral movement path identified'
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT']
| extend FromAccount = AdditionalFields.['FROM.ACCOUNT']
| project
     TimeGenerated,
     LateralMovementPathToSensitiveAccount,
     FromAccount,
     DeviceName,
     AccountName,
     AccountDomain"
$sentinelQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery2
$sentinelQuery2.Results

# Admin 500 account logins

$mdiQuery2 = "DeviceLogonEvents
| where AccountSid endswith '-500' and parse_json(AdditionalFields).IsLocalLogon != true
| join kind=leftanti IdentityLogonEvents on AccountSid // Remove the domain's built-in admin acccount"
$mdiQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdiQuery2
$mdiQuery2.Results

# Top User with Most Interactive Sign Ins

$mdiQuery3 = "IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title='Top 100 users that have the most interactive sign ins')"
$mdiQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdiQuery3
$mdiQuery3.Results

$sentinelQuery3 = "IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title='Top 100 users that have the most interactive sign ins')"
$sentinelQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery3
$sentinelQuery3.Results

# User added to Privileged Group

$mdiQuery4 = "let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType == 'Group Membership changed'
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)"
$mdiQuery4 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdiQuery4
$mdiQuery4.Results

$sentinelQuery4 = "let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where TimeGenerated > ago(30d)
| where ActionType == 'Group Membership changed'
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)"
$sentinelQuery4 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery4
$sentinelQuery4.Results

