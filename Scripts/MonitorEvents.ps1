# Windows Privacy Inspector - Event Monitoring Script
# This script monitors Windows Event Logs for resource access events

param(
    [int]$Duration = 3600,  # Duration in seconds (default 1 hour)
    [string]$LogName = "Security"
)

Write-Host "Windows Privacy Inspector - Event Monitor" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires administrator privileges for full functionality."
}

# Function to parse event and extract resource information
function Parse-ResourceAccessEvent {
    param($Event)
    
    $eventId = $Event.Id
    $timeCreated = $Event.TimeCreated
    $message = $Event.Message
    
    # Check for camera access
    if ($message -match "camera|webcam|video capture" -or $eventId -eq 4656) {
        return @{
            Type = "Camera"
            Time = $timeCreated
            EventId = $eventId
            Message = $message
        }
    }
    
    # Check for microphone access
    if ($message -match "microphone|mic|audio capture" -or $eventId -eq 4656) {
        return @{
            Type = "Microphone"
            Time = $timeCreated
            EventId = $eventId
            Message = $message
        }
    }
    
    # Check for file access
    if ($message -match "file|directory|folder" -or ($eventId -ge 4656 -and $eventId -le 4663)) {
        return @{
            Type = "Files"
            Time = $timeCreated
            EventId = $eventId
            Message = $message
        }
    }
    
    return $null
}

# Monitor events
Write-Host "Starting event log monitoring..." -ForegroundColor Green
Write-Host "Monitoring for $Duration seconds..." -ForegroundColor Yellow
Write-Host ""

$startTime = Get-Date
$endTime = $startTime.AddSeconds($Duration)
$eventCount = 0

try {
    # Query recent events
    $query = "*[System[EventID>=4656 and EventID<=4663]]"
    $events = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$startTime} -ErrorAction SilentlyContinue
    
    if ($events) {
        Write-Host "Found $($events.Count) relevant events" -ForegroundColor Green
        Write-Host ""
        
        foreach ($event in $events) {
            $resourceInfo = Parse-ResourceAccessEvent -Event $event
            if ($resourceInfo) {
                $eventCount++
                Write-Host "[$($resourceInfo.Time)] $($resourceInfo.Type) Access Detected" -ForegroundColor Yellow
                Write-Host "  Event ID: $($resourceInfo.EventId)" -ForegroundColor Gray
                Write-Host ""
            }
        }
    }
    
    # Set up real-time monitoring
    Write-Host "Setting up real-time monitoring..." -ForegroundColor Green
    $action = {
        param($Event)
        $resourceInfo = Parse-ResourceAccessEvent -Event $Event
        if ($resourceInfo) {
            Write-Host "[$($resourceInfo.Time)] ALERT: $($resourceInfo.Type) Access" -ForegroundColor Red
            Write-Host "  Event ID: $($resourceInfo.EventId)" -ForegroundColor Gray
            Write-Host "  Details: $($resourceInfo.Message.Substring(0, [Math]::Min(100, $resourceInfo.Message.Length)))" -ForegroundColor Gray
            Write-Host ""
        }
    }
    
    $query = "*[System[EventID>=4656 and EventID<=4663]]"
    Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='$LogName' AND EventCode>=4656 AND EventCode<=4663" -Action $action -ErrorAction SilentlyContinue
    
    # Wait for duration
    while ((Get-Date) -lt $endTime) {
        Start-Sleep -Seconds 1
    }
    
} catch {
    Write-Error "Error monitoring events: $_"
} finally {
    Write-Host ""
    Write-Host "Monitoring completed. Total events detected: $eventCount" -ForegroundColor Cyan
}

