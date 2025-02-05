# Define the path to the Windows Firewall log file
$logFilePath = "<FW log file path>"
$reportLogPath = "<path to script log>\abuseipdb_reporting.log"

# Your AbuseIPDB API key
$apiKey = "<your api key>"

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

# Function to check if an IP address is within a specific range
function Is-IPInRange {
    param (
        [string]$ip,
        [string]$cidr
    )

    # Validate IP format
    if (-not [IPAddress]::TryParse($ip, [ref]$null)) {
        return $false
    }

    # Split CIDR notation
    $parts = $cidr -split '/'
    if ($parts.Count -ne 2) { return $false }

    $subnetIP = [IPAddress]$parts[0]
    $subnetMaskBits = [int]$parts[1]

    # Validate subnet mask range
    if ($subnetMaskBits -lt 0 -or $subnetMaskBits -gt 32) { return $false }

    # Convert IP and subnet to 32-bit unsigned integers (big-endian)
    $ipBytes = ([IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($ipBytes)  # Convert to big-endian
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    $subnetBytes = $subnetIP.GetAddressBytes()
    [Array]::Reverse($subnetBytes)  # Convert to big-endian
    $subnetInt = [BitConverter]::ToUInt32($subnetBytes, 0)

    # Generate subnet mask
    $mask = [uint32]::MaxValue -shl (32 - $subnetMaskBits)

    # Compare the masked IP with the subnet
    return ($ipInt -band $mask) -eq ($subnetInt -band $mask)
}

# Check if the log file exists
if (Test-Path $logFilePath) {
    # Get the current date and time
    $currentDateTime = Get-Date
    # Calculate the time one hour ago
    $timeThreshold = $currentDateTime.AddHours(-1)

    # Improved IP extraction pattern
	$ipAddresses = Get-Content $logFilePath | Where-Object {
    if ($_ -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})' -and $_ -notmatch "SEND") {
        $logDateTime = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
        return $logDateTime -ge $timeThreshold
    }
    return $false
	} | Select-String -Pattern '(?<=\s|^)(?:\d{1,3}\.){3}\d{1,3}(?=\s|$)' | ForEach-Object {
    $_.Matches.Value
	} | Sort-Object -Unique

    # Define excluded subnets
    $excludedSubnets = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")

    # Report each unique IP address to AbuseIPDB, excluding specific ranges
    foreach ($ip in $ipAddresses) {
        # Exclude the specified IP ranges
        $excluded = $false
        foreach ($subnet in $excludedSubnets) {
            if (Is-IPInRange $ip $subnet) {
                $excluded = $true
                Log-Message "Skipped IP: $ip (within excluded range $subnet)"
                break
            }
        }

        if ($excluded) { continue }

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
    
    # Safe API response logging
    $message = if ($response.data -and $response.data.message) { 
        $response.data.message 
    } else { 
        "No message returned" 
    }
    Log-Message "Reported IP: $ip - Response: $message"
	} catch {
    Log-Message "Failed to report IP: $ip - Error: $($_.Exception.Message)"
	}

        # Introduce a 1-second delay between reports
        Start-Sleep -Seconds 1
    }
} else {
    Log-Message "Log file not found at $logFilePath"
}
