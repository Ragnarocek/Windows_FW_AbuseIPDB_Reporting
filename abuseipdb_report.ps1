# Define the path to the Windows Firewall log file
$logFilePath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
$reportLogPath = "C:\Logs\abuseipdb_reporting.log"

# Your AbuseIPDB API key
$apiKey = "YOUR API KEY HERE"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $reportLogPath -Value $logEntry

    # Circular logging: keep logs for the last 24 hours
    $logEntries = Get-Content $reportLogPath
    $cutoffDate = (Get-Date).AddHours(-24)

    $newLogEntries = @()
    foreach ($entry in $logEntries) {
        # Only attempt to parse entries that start with a valid timestamp format
        if ($entry -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}') {
            try {
                $entryDate = [datetime]::ParseExact($entry.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null)
                if ($entryDate -ge $cutoffDate) {
                    $newLogEntries += $entry
                }
            } catch {
                # Ignore any parsing errors for valid log entries
                Write-Host "Failed to parse log entry: $entry"
            }
        }
    }

    # Rewrite the log file with filtered entries
    Set-Content -Path $reportLogPath -Value $newLogEntries
}

# Function to check if an IP address is in a specific range
function Is-IPInRange {
    param (
        [string]$ip,
        [string]$cidr
    )
    $netmaskBits = [int]($cidr.Split('/')[1])
    $subnet = $cidr.Split('/')[0]

    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    $subnetBytes = [System.Net.IPAddress]::Parse($subnet).GetAddressBytes()

    $ipBinary = [System.BitConverter]::ToUInt32($ipBytes[0..3], 0)
    $subnetBinary = [System.BitConverter]::ToUInt32($subnetBytes[0..3], 0)

    $mask = [math]::pow(2, 32) - [math]::pow(2, 32 - $netmaskBits)
    return ($ipBinary -band $mask) -eq ($subnetBinary -band $mask)
}

# Check if the log file exists
if (Test-Path $logFilePath) {
    # Get the current date and time
    $currentDateTime = Get-Date
    # Calculate the time one hour ago
    $timeThreshold = $currentDateTime.AddHours(-1)

    # Read the log file and filter for IP addresses within the last hour
    $ipAddresses = Get-Content $logFilePath | Where-Object {
        if ($_ -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') {
            $logDateTime = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
            return $logDateTime -ge $timeThreshold
        }
        return $false
    } | Select-String -Pattern '\b(?:\d{1,3}\.){3}\d{1,3}\b' | ForEach-Object {
        $_ -replace '.*?(\b(?:\d{1,3}\.){3}\d{1,3}\b).*', '$1'
    } | Sort-Object -Unique

    # Report each unique IP address to AbuseIPDB, excluding specific ranges
    foreach ($ip in $ipAddresses) {
        # Exclude the specified IP ranges
        if (Is-IPInRange $ip "192.168.0.0/24" -or Is-IPInRange $ip "192.168.1.0/24") {
            Log-Message "Skipped IP: $ip (within excluded range)"
            continue
        }

        $url = "https://api.abuseipdb.com/api/v2/report"
        $comment = "Automatic report from firewall log."
        $categories = "14,15,18"  # Adjust as necessary

        $body = @{
            "ip"        = $ip
            "comment"   = $comment
            "categories" = $categories
        }

        # Log the request
        Log-Message "Sending request for IP: $ip"
        Log-Message "Request Body: $($body | ConvertTo-Json)"

        $headers = @{
            "Key"    = $apiKey
            "Accept" = "application/json"
        }

        try {
            # Send the request
            $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            Log-Message "Reported IP: $ip - Response: $($response.data.message)"
        } catch {
            Log-Message "Failed to report IP: $ip - Error: $_"
        }

        # Introduce a 1-second delay between reports
        Start-Sleep -Seconds 1
    }
} else {
    Log-Message "Log file not found at $logFilePath"
}
