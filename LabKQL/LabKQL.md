This file contains KQL scripts used in the course SC-200: Security Operations Analyst associate, Module 4 - 


# Module 4 - Lab 1 - Exercise 1 - Create queries for Microsoft Sentinel using Kusto Query Language (KQL)

## Lab scenario
You are a Security Operations Analyst working at a company that is implementing Microsoft Sentinel. You are responsible for performing log data analysis to search for malicious activity, display visualizations, and perform threat hunting. To query log data, you use the Kusto Query Language (KQL).

>**Hint:** This lab involves entering many KQL scripts into Microsoft Sentinel. The scripts were provided in a file at the beginning of this lab. An alternate location to download them is:  https://github.com/MicrosoftLearning/SC-200T00A-Microsoft-Security-Operations-Analyst/tree/master/Allfiles


### Task 1: Access the KQL testing area.

In this task, you will access a Log Analytics environment where you can practice writing KQL statements.

1. Login to WIN1 virtual machine as Admin with the password: **Pa55w.rd**.  

2. Go to https://aka.ms/lademo in your browser. Login with the MOD Administrator credentials. 

3. Explore the available tables listed in the tab on the left side of the screen.

4. In the query editor, enter the following query and select the **Run** button.  You should see the query results in the bottom window.

```KQL
SecurityEvent
```

5. Notice that you have reached the maximum number of results (30,000).

6. Change the *Time range* to **Last 30 minutes** in the Query Window.

7. Next to the first record, select the **>** to expand the information for the row.


### Task 2: Run Basic KQL Statements

In this task, you will build basic KQL statements.

>**Important:**  For each query, clear the previous statement from the Query Window or open a new Query Windows by selecting **+** after the last opened tab (up to 25).

1. The following statement demonstrates the **search** operator, which searches all columns in the table for the value. In the Query Window enter the following statement and select **Run**: 

```KQL
search "new"
```

2. The following statement demonstrates searching across tables listed with the "in" clause. Enter the following statement and select **Run**: 

```KQL
search in (SecurityEvent,App*) "new"
```

3. Change back the *Time range* to **Last 24 hours** in the Query Window.

4. The following statements demonstrates the where operator. In the Query Window. Enter the following statement and select **Run**: 

    >**Important:** You should "run" after entering the query from each code block below.

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

5. The following statement demonstrates the use of the let statement to declare variables. In the Query Window. Enter the following statement and select **Run**: 

```KQL
 let timeOffset = 1h;
 let discardEventId = 4688;
 SecurityEvent
 | where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
 | where EventID != discardEventId
```

6. The following statement demonstrates the use of the let statement to declare a dynamic list. In the Query Window enter the following statement and select **Run**: 

```KQL
let suspiciousAccounts = datatable(account: string) [
    @"NA\timadmin", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent 
| where TimeGenerated > ago(1h)
| where Account in (suspiciousAccounts)
```

>**Tip:** You can re-format the query easily by selecting the ellipsis (...) in the Query window and select **Format query**.

7. The following statement demonstrates the use of the "let" statement to declare a dynamic table. In the Query Window. Enter the following statement and select **Run**: 

```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 1000;
LowActivityAccounts | where Account contains "sql"
```

8. Change the **Time range** to **Last hour** in the Query Window. This will limit our results for the following statements.

9. The following statement demonstrates creating fields using the extend operator In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
```

10. The following statement demonstrates sorting results using the order by operator. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) 
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
```

11. The following statements demonstrate specifying fields for the result set using the project operators.

    >**Note:** You should "Run" after entering the query from each code block below.

In the Query Window. Enter the following statement and select **Run**: 

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


### Task 3: Analyze Results in KQL with the Summarize Operator

In this task, you will build KQL statements to prepare data.

1. The following statement demonstrates the count() function. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4688"
| summarize count() by Process, Computer
```

2. The following statement demonstrates the count() function. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4624
| summarize cnt=count() by AccountType, Computer
```

3. The following statement demonstrates the dcount() function. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize dcount(IpAddress)
```

4. The following statement is a rule to detect Invalid password failures across multiple applications for the same account. In the Query Window enter the following statement and select **Run**: 

```KQL
let timeframe = 30d;
let threshold = 1;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

5. The following statement demonstrates the arg_max() function.

The following statement will return the most current row from the SecurityEvent table for the computer SQL10.NA.contosohotels.com.  The * in the arg_max function requests all columns for the row. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```

6. The following statement demonstrates the arg_min() function.

In this statement, the oldest SecurityEvent for the computer SQL10.NA.contosohotels.com will be returned as the result set. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```

7. The following statements demonstrate the importance of understanding results based on the order of the pipe "|". In the Query Window. Enter the following queries and run each separately: 

**Query 1** will have Accounts for which the last activity was a login. The SecurityEvent table will first be summarized and return the most current row for each Account.  Then only rows with EventID equals 4624 (login) will be returned.

```KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"
```

**Query 2** will have the most recent login for Accounts that have logged in.  The SecurityEvent table will be filtered to only include EventID = 4624. Then these results will be summarized for the most current login row by Account.

```KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account
```

>**Note:**  You can also review the "Total CPU" and "Data used for processed query" by selecting the bar "Completed" and compare the data between both statements.

8. The following statement demonstrates the make_list() function.

The make_list function returns a dynamic (JSON) array of all the values of Expression in the group. This KQL query will first filter the EventID with the where operator.  Next, for each Computer, the results are a JSON array of Accounts. The resulting JSON array will include duplicate accounts.

In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_list(Account) by Computer
```

9. The following statement demonstrates the make_set() function.

The make_set function returns a dynamic (JSON) array containing *distinct* values that Expression takes in the group. This KQL query will first filter the EventID with the where operator.  Next, for each Computer, the results are a JSON array of unique Accounts. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_set(Account) by Computer
```

### Task 4: Create visualizations in KQL with the Render Operator

In this task, you will use generate visualizations with KQL statements.

1. The following statement demonstrates the render operator visualizing results with a barchart. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by Account
| render barchart
```

2. The following statement demonstrates the render operator visualizing results with a time series.

The bin() function rounds values down to an integer multiple of the given bin size.  Used frequently in combination with summarize by .... If you have a scattered set of values, the values are grouped into a smaller set of specific values.  Combining the generated time series and pipe to a render operator with a type of timechart provides a time series visualization. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 1m) 
| render timechart
```


### Task 5: Build multi-table statements in KQL

In this task, you will build multi-table KQL statements.

1. The following statement demonstrates the union operator that takes two or more tables and returns the rows of all of them. Understanding how results are passed and impacted with the pipe character is essential. In the Query Window. Enter the following statements and select **Run** for each separately to see the results: 

**Query 1** will return all rows of SecurityEvent and all rows of SigninLogs.

```KQL
SecurityEvent 
| union SigninLogs  
```

**Query 2** will return one row and column, which is the count of all rows of SecurityEvent and all rows of SigninLogs.

```KQL
SecurityEvent 
| union SigninLogs  
| summarize count() 
```

**Query 3** will return all rows of SecurityEvent and one row for SigninLogs.  The row for SigninLogs will have the count of the SigninLogs rows.

```KQL
SecurityEvent 
| union (SigninLogs | summarize count() | project count_)
```

2. The following statement demonstrates the union operator support for wildcards to union multiple tables. In the Query Window. Enter the following statement and select **Run**: 

```KQL
union Security* 
| summarize count() by Type
```

3. The following statement demonstrates the join operator, which merges the rows of two tables to form a new table by matching the specified columns' values from each table. In the Query Window. Enter the following statement and select **Run**: 

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

The first table specified in the join is considered the Left table.  The table after the join keyword is the right table.  When working with columns from the tables, the $left.Column name and $right.Column name is to distinguish which tables column are referenced. 


### Task 6: Work with string data in KQL

In this task, you will work with structured and unstructured string fields with KQL statements.

1. The following statement demonstrates the extract function().  Extract gets a match for a regular expression from a text string. You have the option to convert the extracted substring to the indicated type. In the Query Window. Enter the following statement and select **Run**: 

```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

2. The following statements use the extract() function to pull out the Account Name from the Account field of the SecurityEvent table. In the Query Window. Enter the following statement and select **Run**: 

```KQL
SecurityEvent
| where EventID == 4672 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize LoginCount = count() by Account_Name
| where Account_Name != ""
| where LoginCount < 10
```

3. The following statement demonstrates the parse operator. Parse evaluates a string expression and parses its value into one or more calculated columns. The computed columns will have nulls for unsuccessfully parsed strings.

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

4. The following statement demonstrates working with dynamic fields, which are special since they can take on any value of other data types. In this example, The DeviceDetail field from the SigninLogs table is of type dynamic. In the Query Window enter the following statement and select Run: 


```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem
```

5. The following example shows how to break out packed fields for SigninLogs. In the Query Window enter the following statement and select Run:


```KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend Date = startofday(TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
```

6. The following statement demonstrates operators to manipulate JSON stored in string fields. Many logs submit data in JSON format, which requires you to know how to transform JSON data to queryable fields. 

In the Query Window. Enter the following statements individually and select **Run**: 

```KQL
 SigninLogs
| extend AuthDetails = todynamic(AuthenticationDetails)
| extend AuthMethod =  AuthDetails[0].authenticationMethod 
| extend AuthResult = AuthDetails[0].["authenticationStepResultDetail"] 
| project AuthMethod, AuthResult, AuthDetails
```
The mv-expand operator expands multi-value dynamic arrays or property bags into multiple records.

```KQL
 SigninLogs
| mv-expand AuthDetails = todynamic(AuthenticationDetails)
| project AuthDetails
```
The mv-apply operator applies a subquery to each record and returns the union of the results of all subqueries.

```KQL
SigninLogs
| mv-apply AuthDetails = todynamic(AuthenticationDetails) on 
(where AuthDetails.authenticationMethod == "Password")
```

7. To create a function:

    >**Note:** You will not be able to do this in the lademo environment used for data in this lab, but it's an important concept to be used in your environment. 

After running a query, select the **Save** button and then select **Save As function** from the drop-down. Enter the name your want, for example: *PrivLogins* in the **Function name** box and enter a **Legacy category**, like *General* and select **Save**.

The function will be available in KQL by using the function alias:

```KQL
PrivLogins
```

## You have completed the lab.
