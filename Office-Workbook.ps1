Connect-AzAccount
$sub = Get-azsubscription
Set-AzContext -Subscription $sub
$workspaceName = "sc200"
$workspaceRG = "sc-200"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Malware Activity

$mdeQuery = 'OfficeActivity
| where Operation == "FileMalwareDetected"
| project-reorder TimeGenerated, OfficeWorkload, SourceFileName, OfficeObjectId, UserId'
$mdeQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery
$mdeQuery.Results


# Check for exe/dll/scr, ps1, vbs, js in Office

$mdeQuery1 = 'DeviceEvents
| where ActionType in ("AsrExecutableEmailContentBlocked", "AsrExecutableEmailContentAudited")
// join the information from the email attachment
| join kind=inner (EmailAttachmentInfo
     | project NetworkMessageId, FileName, SHA256, FileSize)
     on $left.FileName == $right.FileName
// join the email information     
| join kind=inner (EmailEvents
     | project SenderFromAddress, Subject, NetworkMessageId)
     on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder SenderFromAddress, Subject, FileName, FileSize, SHA256'

$mdeQuery1 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery1
$mdeQuery1.Results

$sentinelQuery1 = 'DeviceEvents
| where ActionType in ("AsrExecutableEmailContentBlocked", "AsrExecutableEmailContentAudited")
// join the information from the email attachment
| join kind=inner (EmailAttachmentInfo
     | project NetworkMessageId, FileName, SHA256, FileSize)
     on $left.FileName == $right.FileName
// join the email information     
| join kind=inner (EmailEvents
     | project SenderFromAddress, Subject, NetworkMessageId)
     on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder SenderFromAddress, Subject, FileName, FileSize, SHA256'
$sentinelQuery1 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery1
$sentinelQuery1.Results

# SafeLinks URL Blocked/Trigger

$mdeQuery2 = "UrlClickEvents
| where ActionType == 'ClickBlocked'
// Only filter on Safe Links actions from mail
| where Workload == 'Email'
// join the email events
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress) on NetworkMessageId
| project Timestamp, AccountUpn, Product = Workload, Url, ThreatTypes, Subject, SenderFromAddress, UrlChain"
$mdeQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery2
$mdeQuery2.Results

$sentinelQuery2 = "UrlClickEvents
| where ActionType == 'ClickBlocked'
// Only filter on Safe Links actions from mail
| where Workload == 'Email'
// join the email events
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress) on NetworkMessageId
| project TimeGenerated, AccountUpn, Product = Workload, Url, ThreatTypes, Subject, SenderFromAddress, UrlChain"
$sentinelQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery2
$sentinelQuery2.Results

# Inboxes that Got an ISO

$mdeQuery3 = "EmailEvents
| where EmailDirection == 'Inbound'
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project
     Timestamp,
     NetworkMessageId,
     SenderFromAddress,
     SenderIPv4,
     SenderIPv6,
     RecipientEmailAddress,
     Subject,
     FileName,
     FileType,
     ThreatNames
| where FileName endswith '.iso'"
 $mdeQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery3
 $mdeQuery3.Results

 $sentinelQuery3 = "EmailEvents
 | where EmailDirection == 'Inbound'
 | join kind=inner EmailAttachmentInfo on NetworkMessageId
 | project
      TimeGenerated,
      NetworkMessageId,
      SenderFromAddress,
      SenderIPv4,
      SenderIPv6,
      RecipientEmailAddress,
      Subject,
      FileName,
      FileType,
      ThreatNames
 | where FileName endswith '.iso'"
 $sentinelQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $sentinelQuery3
 $sentinelQuery3.Results