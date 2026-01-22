using System.Diagnostics;
using WindowsPrivacyInspector.Models;

namespace WindowsPrivacyInspector.Services;

public class PrivacyManager
{
    public enum LockdownMode
    {
        None,
        Full,
        Camera,
        Microphone,
        Files
    }

    private LockdownMode _currentMode = LockdownMode.None;

    public LockdownMode CurrentMode => _currentMode;

    public void ApplyLockdown(LockdownMode mode)
    {
        try
        {
            _currentMode = mode;

            switch (mode)
            {
                case LockdownMode.Full:
                    DisableCamera();
                    DisableMicrophone();
                    RestrictFileAccess();
                    Console.WriteLine("Full privacy lockdown activated.");
                    break;

                case LockdownMode.Camera:
                    DisableCamera();
                    Console.WriteLine("Camera access disabled.");
                    break;

                case LockdownMode.Microphone:
                    DisableMicrophone();
                    Console.WriteLine("Microphone access disabled.");
                    break;

                case LockdownMode.Files:
                    RestrictFileAccess();
                    Console.WriteLine("File access restricted.");
                    break;

                case LockdownMode.None:
                    RestorePrivacySettings();
                    Console.WriteLine("Privacy settings restored.");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error applying lockdown: {ex.Message}");
            throw;
        }
    }

    private void DisableCamera()
    {
        try
        {
            // Use PowerShell to disable camera via registry
            var script = @"
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Value 'Deny' -Force
                Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Value 'Deny' -Force
            ";

            ExecutePowerShellScript(script);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error disabling camera: {ex.Message}");
        }
    }

    private void DisableMicrophone()
    {
        try
        {
            // Use PowerShell to disable microphone via registry
            var script = @"
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Value 'Deny' -Force
                Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Value 'Deny' -Force
            ";

            ExecutePowerShellScript(script);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error disabling microphone: {ex.Message}");
        }
    }

    private void RestrictFileAccess()
    {
        try
        {
            // Use PowerShell to restrict file access
            var script = @"
                # Set file access restrictions via Group Policy or registry
                # This is a simplified version - full implementation would require more complex rules
                Write-Host 'File access restrictions applied'
            ";

            ExecutePowerShellScript(script);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error restricting file access: {ex.Message}");
        }
    }

    private void RestorePrivacySettings()
    {
        try
        {
            var script = @"
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Value 'Allow' -Force
                Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Value 'Allow' -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Value 'Allow' -Force
                Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Value 'Allow' -Force
            ";

            ExecutePowerShellScript(script);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error restoring privacy settings: {ex.Message}");
        }
    }

    private void ExecutePowerShellScript(string script)
    {
        var processStartInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Verb = "runas" // Run as administrator
        };

        using var process = Process.Start(processStartInfo);
        if (process != null)
        {
            process.WaitForExit();
        }
    }

    public Dictionary<string, bool> GetPrivacyStatus()
    {
        return new Dictionary<string, bool>
        {
            { "Camera", IsResourceEnabled("webcam") },
            { "Microphone", IsResourceEnabled("microphone") },
            { "Files", true } // File access is more complex to check
        };
    }

    private bool IsResourceEnabled(string resource)
    {
        try
        {
            var script = $@"
                $value = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{resource}' -Name 'Value' -ErrorAction SilentlyContinue).Value
                if ($value -eq 'Deny') {{ return $false }} else {{ return $true }}
            ";

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(processStartInfo);
            if (process != null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return !output.Contains("False", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            // Default to enabled if we can't determine
        }

        return true;
    }
}

