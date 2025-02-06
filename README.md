# Windows_FW_AbuseIPDB_Reporting
Powershell script for reporting dropped connections from Windows Firewall logs to the abuseipdb.com website.  
  
The script is intended to run and report the ip addresses once per hour (you can use the Task Scheduler for setting the run time).  
  
___Editable variables:___  
Line #2: $logFilePath - location of your FW log files  
Line #3: $reportLogPath - location where the log files of this script will be located  
Line #6: $apiKey - this key MUST be edited, paste your AbuseIPDB key between the quotation marks, delete the YOUR API KEY HERE text from the string of course  
Line #84: $timeThreshold - timeframe for reading the FW log (default is last 1hr)  
Line #98: $excludedSubnets - definition of the subnets excluded from reporting  
Line #115: $comment - this string will be sent as comment to your report, do not leave this string empty  
Line #116: $categories - reported categories, you can find more about the categories here: https://www.abuseipdb.com/categories  


___How to enable logging of the dropped packets in Windows Firewall:___  
___NOTE:___ This is relevant if the customer is using Windows Firewall functions and features.  
1. Launch Windows Firewall with Advanced Security.  
2. Click [Action].  
3. Click [Properties].  
4. Choose your profile tab, click "Customize" under Logging.  
5. On the "Log dropped packets" drop down, select "Yes".  
6. On the same window, note where it says "Default path for the log file is:", as this is where the log file will be stored when it is generated.  
7. Profit ! 
