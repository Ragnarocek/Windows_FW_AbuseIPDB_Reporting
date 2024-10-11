# Windows_FW_AbuseIPBD_Reporting
Powershell script for reporting dropped connections from Windows Firewall logs to the abuseipdb.com website.  
  
The script is intended to run and report the ip addresses once per hour (you can use the Task Scheduler for setting the run time).  
  
Editable variables:  
Line #2: $logFilePath - location of your FW log files  
Line #3: $reportLogPath - location where the log files of this script will be located  
Line #6: $apiKey - this key MUST be edited, paste your AbuseIPDB key between the quotation marks, delete the YOUR API KEY HERE text from the string of course  
Line #65: $timeThreshold - timeframe for reading the FW log (default is last 1hr)  
Line #90: $excludedSubnets - definition of the subnets excluded from reporting  
Line #87: $comment - this string will be sent as comment to your report, do not leave this string empty  
Line #88: $categories - reported categories, you can find more about the categories here: https://www.abuseipdb.com/categories  
