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

 # Doc Attachment w/ Download Link Last 14 days
#  // This query looks for a Word document attachment, from which a link was clicked, and after which there was a browser download.
# // This query is not noisy, but most of its results are clean.
# // It can also hserve as reference for other queries on email attachments, on browser downloads or for queries that join multiple events by time.
# // Tags: #EmailAttachment, #WordLink, #BrowserDownload, #Phishing, #DedupFileCreate
# // Implementation comment #1: Matching events by time
# //      Matching the 3 different events (saving attachment, clicking on link, downloading file) is done purely by time difference - so could sometimes link together unrelated events.
# //      Doing a more exact lookup would create a much more complex query due to 
# // Implementation comment #2: Deduping DeviceFileEvents
# //      Oftentimes there are multiple DeviceFileEvents for a single file - e.g. if the file keeps being appended into before being closed.
# //      So, we query only for the last reported file state to ignore intermediate file states.
# // Explaining the underlying data:
# //     BrowserLaunchedToOpenUrl event:
# //         This query uses the BrowserLaunchedToOpenUrl event, that includes clicks on http:// or https:// links (clicks outside of browsers), or on .lnk files
# //         For this event, RemoteUrl contains the opened URL.
$docAttachQuery = 'let minTimeRange = ago(14d);
let wordLinks = 
    DeviceEvents
    // Filter on click on links from WinWord
    | where Timestamp > minTimeRange and ActionType == "BrowserLaunchedToOpenUrl" and isnotempty(RemoteUrl) and InitiatingProcessFileName =~ "winword.exe"
    | project ClickTime=Timestamp, DeviceId, DeviceName, ClickUrl=RemoteUrl;
let docAttachments = 
    DeviceFileEvents
    | where Timestamp > minTimeRange 
			// Query for common document file extensions
            and (FileName endswith ".docx" or FileName endswith ".docm" or FileName endswith ".doc")
			// Query for files saved from email clients such as the Office Outlook app or the Windows Mail app
            and InitiatingProcessFileName in~ ("outlook.exe", "hxoutlook.exe")
    | summarize AttachmentSaveTime=min(Timestamp) by AttachmentName=FileName, DeviceId;
let browserDownloads = 
    DeviceFileEvents
    | where Timestamp > minTimeRange 
			// Query for files created by common browsers
            and InitiatingProcessFileName in~ ("browser_broker.exe", "chrome.exe", "iexplore.exe", "firefox.exe")
            // Exclude JS files that are used for loading sites (but still query for JS files that are known to be downloaded)
            and not (FileName endswith ".js" and isempty(FileOriginUrl))
    // Further filter to exclude file extensions that are less indicative of an attack (when there were already previously a doc attachment that included a link)
    | where FileName !endswith ".partial" and FileName !endswith ".docx"
    | summarize (Timestamp, SHA1) = argmax(Timestamp, SHA1) by FileName, DeviceId, FileOriginUrl;
// Perf tip: start the joins from the smallest table (put it on the left-most side of the joins)
wordLinks
| join kind= inner (docAttachments) on DeviceId | where ClickTime - AttachmentSaveTime between (0min..3min)
| join kind= inner (browserDownloads) on DeviceId | where Timestamp - ClickTime between (0min..3min) 
// Aggregating multiple "attachments" together - because oftentimes the same file is stored multiple times under different names
| summarize Attachments=makeset(AttachmentName), AttachmentSaveTime=min(AttachmentSaveTime), ClickTime=min(ClickTime)
    by // Downloaded file details
        bin(Timestamp, 1tick), FileName, FileOriginUrl, ClickUrl, SHA1, DeviceName, DeviceId'
        $docAttachQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $docAttachQuery
        $docAttachQuery.Results

#    // This query looks for user content downloads from dropbox that originate from a link/redirect from a 3rd party site.
#    // File sharing sites such as Dropbox are often used for hosting malware on a reputable site.
#    // Read more about download URL data and about this attack vector in this blog post:
#    // https://techcommunity.microsoft.com/t5/Threat-Intelligence/Hunting-tip-of-the-month-Browser-downloads/td-p/220454
#    // Tags: #DownloadUrl, #Referer, #Dropbox
$dropBoxRedirectQuery =  'DeviceFileEvents
        | where 
            Timestamp > ago(7d)
            and FileOriginUrl startswith "https://dl.dropboxusercontent.com/"
            and isnotempty(FileOriginReferrerUrl)
            and FileOriginReferrerUrl !startswith "https://www.dropbox.com/" 
        | project FileOriginReferrerUrl, FileName'
        $dropBoxRedirectQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $dropBoxRedirectQuery
        $dropBoxRedirectQuery.Results

     #    // Pivot from downloads detected by Windows Defender Antivirus to other files downloaded from the same sites
     #    // To learn more about the download URL info that is available and see other sample queries,
     #    // check out this blog post: https://techcommunity.microsoft.com/t5/Threat-Intelligence/Hunting-tip-of-the-month-Browser-downloads/td-p/220454
     #    let detectedDownloads =
            $downloadPivotQuery = 'DeviceEvents
            | where ActionType == "AntivirusDetection" and isnotempty(FileOriginUrl)
            | project Timestamp, FileOriginUrl, FileName, DeviceId,
                      ThreatName=tostring(parse_json(AdditionalFields).ThreatName)
            // Filter out less severe threat categories on which we do not want to pivot
            | where ThreatName !startswith "PUA"
                    and ThreatName !startswith "SoftwareBundler:" 
                    and FileOriginUrl != "about:internet";
        let detectedDownloadsSummary =
            detectedDownloads
            // Get a few examples for each detected Host:
            // up to 4 filenames, up to 4 threat names, one full URL)
            | summarize DetectedUrl=any(FileOriginUrl),
                        DetectedFiles=makeset(FileName, 4),
                        ThreatNames=makeset(ThreatName, 4)
                        by Host=tostring(parse_url(FileOriginUrl).Host);
        // Query for downloads from sites from which other downloads were detected by Windows Defender Antivirus
        DeviceFileEvents
        | where isnotempty(FileOriginUrl)
        | project FileName, FileOriginUrl, DeviceId, Timestamp,
                  Host=tostring(parse_url(FileOriginUrl).Host), SHA1 
        // Filter downloads from hosts serving detected files
        | join kind=inner(detectedDownloadsSummary) on Host
        // Filter out download file create events that were also detected.
        // This is needed because sometimes both of these events will be reported, 
        // and sometimes only the AntivirusDetection event - depending on timing.
        | join kind=leftanti(detectedDownloads) on DeviceId, FileOriginUrl
        // Summarize a single row per host - with the machines count 
        // and an example event for a missed download (select the last event)
        | summarize MachineCount=dcount(DeviceId), arg_max(Timestamp, *) by Host
        // Filter out common hosts, as they probably ones that also serve benign files
        | where MachineCount < 20
        | project Host, MachineCount, DeviceId, FileName, DetectedFiles, 
                  FileOriginUrl, DetectedUrl, ThreatNames, Timestamp, SHA1
        | order by MachineCount desc'
        $downloadPivotQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $downloadPivotQuery
        $downloadPivotQuery.Results

         