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
        if ($entry -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
            try {
                $entryDate = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
                if ($entryDate -ge $cutoffDate) {
                    $newLogEntries += $entry
                }
            } catch {
                Write-Host "Failed to parse log entry: $entry"
            }
        }
    }

    Set-Content -Path $reportLogPath -Value $newLogEntries
}

# Function to check if an IP address is within a specific range
function Is-IPInRange {
    param (
        [string]$ip,
        [string]$cidr
    )
    
    $parts = $cidr -split '/'
    if ($parts.Count -ne 2) { return $false }

    $subnetIP = [IPAddress]$parts[0]
    $subnetMaskBits = [int]$parts[1]
    
    if ($subnetMaskBits -lt 0 -or $subnetMaskBits -gt 32) { return $false }

    $ipBytes = ([IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    $subnetBytes = $subnetIP.GetAddressBytes()
    [Array]::Reverse($subnetBytes)
    $subnetInt = [BitConverter]::ToUInt32($subnetBytes, 0)

    $mask = [uint32]::MaxValue -shl (32 - $subnetMaskBits)
    return ($ipInt -band $mask) -eq ($subnetInt -band $mask)
}

# Check if the log file exists
if (Test-Path $logFilePath) {
$currentDateTime = Get-Date
$timeThreshold = $currentDateTime.AddHours(-1)

$entries = Get-Content $logFilePath | Where-Object {
	if ($_ -match '^(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+DROP\s+TCP\s+(?<ip>(\d{1,3}\.){3}\d{1,3})') {
		$rawTimestamp = $matches['timestamp']
		$ipAddress = $matches['ip']
			if ($rawTimestamp -and $ipAddress) {
			try {
				$logDateTime = [datetime]::ParseExact($rawTimestamp, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
				return $logDateTime -ge $timeThreshold
			} catch {
				Log-Message "Failed to parse timestamp: '$rawTimestamp' in line: $_"
				return $false
			}
		}
	}
	return $false
} | ForEach-Object {
	try {
		$parsedTimestamp = [datetime]::ParseExact($matches['timestamp'], 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
		[PSCustomObject]@{
			Timestamp = $parsedTimestamp.ToString("yyyy-MM-ddTHH:mm:sszzz")  # Format for AbuseIPDB
			IP = $matches['ip']
		}
	} catch {
		Log-Message "Skipping entry due to timestamp parsing failure: $_"
	}
} | Sort-Object IP, Timestamp -Unique

	$excludedSubnets = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")

    foreach ($entry in $entries) {
        $ip = $entry.IP
        $timestamp = $entry.Timestamp
        
        $excluded = $excludedSubnets | Where-Object { Is-IPInRange $ip $_ }
        if ($excluded) {
            Log-Message "Skipped IP: $ip (within excluded range)"
            continue
        }
        
	$logEntryPattern = [regex]::Escape("Reported IP: $ip ")
	if (Select-String -Path $reportLogPath -Pattern $logEntryPattern -Quiet) {
    #Log-Message "Skipping already reported IP: $ip"
		continue
	}
        
        $url = "https://api.abuseipdb.com/api/v2/report"
        $comment = "Automatic report from firewall log."
        $categories = "14,15,18"

        $body = @{
            "ip"         = $ip
            "timestamp"  = $timestamp
            "comment"    = $comment
            "categories" = $categories
        }

        Log-Message "Sending request for IP: $ip at $timestamp"
        Log-Message "Request Body: $($body | ConvertTo-Json)"

        $headers = @{
            "Key"    = $apiKey
            "Accept" = "application/json"
        }

        try {
            $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            $message = if ($response.data -and $response.data.message) { $response.data.message } else { "No message returned" }
            Log-Message "Reported IP: $ip at $timestamp - Response: $message"
        } catch {
            Log-Message "Failed to report IP: $ip at $timestamp - Error: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 1
    }
} else {
    Log-Message "Log file not found at $logFilePath"
}
