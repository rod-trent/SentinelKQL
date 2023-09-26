## KQL Queries for the Microsoft Sentinel module of the Microsoft Ignite Pre-day Security Workshop
#### Use the copy option (to the right of each code box) to copy the query to paste into the pre-day workshop lab environment.


```KQL
SecurityEvent
```

The following statement demonstrates the **search** operator:

```KQL
search "new"
```

The following statement demonstrates searching across tables: 

```KQL
search in (SecurityEvent,App*) "new"
```

The following statements demonstrates the where operator

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

The following statement demonstrates the use of the let statement to declare variables:

```KQL
 let timeOffset = 1h;
 let discardEventId = 4688;
 SecurityEvent
 | where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
 | where EventID != discardEventId
```

The following statement demonstrates the use of the let statement to declare a dynamic list:

```KQL
let suspiciousAccounts = datatable(account: string) [
    @"NA\timadmin", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent 
| where TimeGenerated > ago(1h)
| where Account in (suspiciousAccounts)
```

The following statement demonstrates the use of the "let" statement to declare a dynamic table: 

```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 1000;
LowActivityAccounts | where Account contains "sql"
```

The following statement demonstrates creating fields using the extend operator: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
```

The following statement demonstrates sorting results using the order by operator: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
```

The following statements demonstrate specifying fields in the results:
    

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

The following statements demonstrates the count() function: 

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

The following statement demonstrates the dcount() function: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize dcount(IpAddress)
```

The following statement is a rule to detect Invalid password failures:

```KQL
let timeframe = 30d;
let threshold = 1;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

The following statement demonstrates the arg_max() function:

```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```

The following statement demonstrates the arg_min() function:

```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```

The following statements demonstrate the importance of understanding results based on the order of the pipe "|":

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

The following statement demonstrates the make_list() function:

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_list(Account) by Computer
```

The following statement demonstrates the make_set() function:

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_set(Account) by Computer
```

The following statement demonstrates the render operator visualizing results with a barchart:

```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by Account
| render barchart
```

The following statement demonstrates the render operator visualizing results with a time series:

```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 1m) 
| render timechart
```

The following statements demonstrates the union operator:

```KQL
SecurityEvent 
| union SigninLogs  
```

```KQL
SecurityEvent 
| union SigninLogs  
| summarize count() 
```

```KQL
SecurityEvent 
| union (SigninLogs | summarize count() | project count_)
```

```KQL
union Security* 
| summarize count() by Type
```

The following statement demonstrates the join operator:

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

The following statement demonstrates the extract function():

```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

The following statements use the extend function:

```KQL
SecurityEvent
| where EventID == 4672 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize LoginCount = count() by Account_Name
| where Account_Name != ""
| where LoginCount < 10
```

The following statement demonstrates the parse operator:

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

The following statement demonstrates working with dynamic fields:

```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem
```

The following example shows how to break out packed fields:

```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend Date = startofday(TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
```

The following statement demonstrates operators to manipulate JSON stored in string fields:

```KQL
 SigninLogs
| extend AuthDetails = todynamic(AuthenticationDetails)
| extend AuthMethod =  AuthDetails[0].authenticationMethod 
| extend AuthResult = AuthDetails[0].["authenticationStepResultDetail"] 
| project AuthMethod, AuthResult, AuthDetails
```
The mv-expand operator expands multi-value dynamic arrays or property bags into multiple records:

```KQL
 SigninLogs
| mv-expand AuthDetails = todynamic(AuthenticationDetails)
| project AuthDetails
```
The mv-apply operator applies a subquery to each record and returns the union of the results of all subqueries:

```KQL
SigninLogs
| mv-apply AuthDetails = todynamic(AuthenticationDetails) on 
(where AuthDetails.authenticationMethod == "Password")
```

To create a function:

```KQL
PrivLogins
```

