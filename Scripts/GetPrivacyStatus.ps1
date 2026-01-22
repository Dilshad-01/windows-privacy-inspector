# Windows Privacy Inspector - Privacy Status Check Script
# This script checks the current privacy settings status

Write-Host "Windows Privacy Inspector - Privacy Status" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Get-PrivacyStatus {
    param(
        [string]$ResourceName,
        [string]$RegistryPath
    )
    
    $status = "Unknown"
    $color = "Gray"
    
    if (Test-Path $RegistryPath) {
        $value = (Get-ItemProperty -Path $RegistryPath -Name "Value" -ErrorAction SilentlyContinue).Value
        
        if ($value -eq "Deny") {
            $status = "Disabled"
            $color = "Red"
        } elseif ($value -eq "Allow") {
            $status = "Enabled"
            $color = "Green"
        } else {
            $status = "Not Set"
            $color = "Yellow"
        }
    } else {
        $status = "Not Configured"
        $color = "Yellow"
    }
    
    Write-Host "$ResourceName`: " -NoNewline
    Write-Host $status -ForegroundColor $color
}

# Check camera status
$cameraPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
Get-PrivacyStatus -ResourceName "Camera" -RegistryPath $cameraPath

# Check microphone status
$microphonePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
Get-PrivacyStatus -ResourceName "Microphone" -RegistryPath $microphonePath

# Check location status
$locationPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
Get-PrivacyStatus -ResourceName "Location" -RegistryPath $locationPath

Write-Host ""
Write-Host "Note: File access restrictions are more complex and may require additional checks." -ForegroundColor Gray

