## KQL Queries for the Microsoft Sentinel module of the Microsoft Ignite Pre-day Security Workshop
#### Use the copy option (to the right of each code box) to copy the query to paste into the pre-day workshop lab environment.


```KQL
SecurityEvent
```

The following statement demonstrates the search operator:
```KQL
search "new"
```

The following statement demonstrates search across tables:
```KQL
search in (SecurityEvent,App*) "new"
```


```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"
```

```KQL
SecurityEvent 
| where TimeGenerated > ago(1h) and EventID in (4624, 4625)
```


```KQL
 let timeOffset = 1h;
 let discardEventId = 4688;
 SecurityEvent
 | where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
 | where EventID != discardEventId
```

```KQL
let suspiciousAccounts = datatable(account: string) [
    @"NA\timadmin", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent 
| where TimeGenerated > ago(1h)
| where Account in (suspiciousAccounts)
```


```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 1000;
LowActivityAccounts | where Account contains "sql"
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| project Computer, Account
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
| project Process, StartDir
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
| project-away ProcessName
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4688"
| summarize count() by Process, Computer
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4624
| summarize cnt=count() by AccountType, Computer
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize dcount(IpAddress)
```


```KQL
let timeframe = 30d;
let threshold = 1;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```



```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```


```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```


```KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"
```


```KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_list(Account) by Computer
```



```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_set(Account) by Computer
```



```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by Account
| render barchart
```



```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 1m) 
| render timechart
```



```KQL
SecurityEvent 
| union SigninLogs  
```


```KQL
SecurityEvent 
| union SigninLogs  
| summarize count() 
```


```KQL
SecurityEvent 
| union (SigninLogs | summarize count() | project count_)
```


```KQL
union Security* 
| summarize count() by Type
```


```KQL
SecurityEvent 
| where EventID == "4624" 
| summarize LogOnCount=count() by EventID, Account 
| project LogOnCount, Account 
| join kind = inner (
SecurityEvent 
| where EventID == "4634" 
| summarize LogOffCount=count() by EventID, Account 
| project LogOffCount, Account 
) on Account
```


```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```


```KQL
SecurityEvent
| where EventID == 4672 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize LoginCount = count() by Account_Name
| where Account_Name != ""
| where LoginCount < 10
```


```KQL
let Traces = datatable(EventText:string)
[
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=23, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=15, lockTime=02/17/2016 08:40:00, releaseTime=02/17/2016 08:40:00, previousLockTime=02/17/2016 08:39:00)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=20, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=22, lockTime=02/17/2016 08:41:01, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=16, lockTime=02/17/2016 08:41:00, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:00)"
];
Traces  
| parse EventText with * "resourceName=" resourceName ", totalSlices=" totalSlices:long * "sliceNumber=" sliceNumber:long * "lockTime=" lockTime ", releaseTime=" releaseTime:date "," * "previousLockTime=" previousLockTime:date ")" *  
| project resourceName, totalSlices, sliceNumber, lockTime, releaseTime, previousLockTime
```


```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem
```


```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend Date = startofday(TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
```


```KQL
 SigninLogs
| extend AuthDetails = todynamic(AuthenticationDetails)
| extend AuthMethod =  AuthDetails[0].authenticationMethod 
| extend AuthResult = AuthDetails[0].["authenticationStepResultDetail"] 
| project AuthMethod, AuthResult, AuthDetails
```


```KQL
 SigninLogs
| mv-expand AuthDetails = todynamic(AuthenticationDetails)
| project AuthDetails
```


```KQL
SigninLogs
| mv-apply AuthDetails = todynamic(AuthenticationDetails) on 
(where AuthDetails.authenticationMethod == "Password")
```



```KQL
PrivLogins
```


