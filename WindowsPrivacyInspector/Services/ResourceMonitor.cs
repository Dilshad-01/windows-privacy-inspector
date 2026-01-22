using System.Diagnostics;
using System.Management;
using WindowsPrivacyInspector.Models;

namespace WindowsPrivacyInspector.Services;

public class ResourceMonitor
{
    private readonly List<AccessEvent> _accessEvents = new();
    private Timer? _monitoringTimer;
    private bool _isMonitoring = false;
    private readonly HashSet<string> _knownProcesses = new();

    public event EventHandler<AccessEvent>? AccessDetected;
    public event EventHandler<AccessEvent>? SuspiciousActivityDetected;

    public void StartMonitoring()
    {
        if (_isMonitoring)
            return;

        try
        {
            _isMonitoring = true;
            // Poll every 2 seconds for active camera/mic usage
            _monitoringTimer = new Timer(CheckResourceUsage, null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
            Console.WriteLine("Resource monitoring started (checking every 2 seconds)...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error starting resource monitor: {ex.Message}");
            throw;
        }
    }

    public void StopMonitoring()
    {
        if (!_isMonitoring || _monitoringTimer == null)
            return;

        _monitoringTimer.Dispose();
        _monitoringTimer = null;
        _isMonitoring = false;

        Console.WriteLine("Resource monitoring stopped.");
    }

    private void CheckResourceUsage(object? state)
    {
        try
        {
            CheckCameraUsage();
            CheckMicrophoneUsage();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking resource usage: {ex.Message}");
        }
    }

    private void CheckCameraUsage()
    {
        try
        {
            // Check for processes using camera devices
            var processes = GetProcessesUsingDevice("Camera", "USB", "Video");
            
            foreach (var process in processes)
            {
                var processKey = $"CAMERA_{process.ProcessName}_{process.Id}";
                
                if (!_knownProcesses.Contains(processKey))
                {
                    _knownProcesses.Add(processKey);
                    
                    var accessEvent = new AccessEvent
                    {
                        Timestamp = DateTime.Now,
                        ApplicationName = process.ProcessName + ".exe",
                        ProcessId = process.Id.ToString(),
                        ResourceType = ResourceType.Camera,
                        AccessType = AccessType.Read,
                        Details = $"Camera access detected - Process: {process.ProcessName}, PID: {process.Id}",
                        IsSuspicious = CheckSuspiciousBehavior(process.ProcessName)
                    };

                    _accessEvents.Add(accessEvent);
                    AccessDetected?.Invoke(this, accessEvent);

                    if (accessEvent.IsSuspicious)
                    {
                        SuspiciousActivityDetected?.Invoke(this, accessEvent);
                    }
                }
            }

            // Clean up processes that are no longer running
            CleanupStaleProcesses("CAMERA_");
        }
        catch
        {
            // Silently handle errors to avoid spam
        }
    }

    private void CheckMicrophoneUsage()
    {
        try
        {
            // Check for processes using microphone devices
            var processes = GetProcessesUsingDevice("Microphone", "Audio", "Recording");
            
            foreach (var process in processes)
            {
                var processKey = $"MIC_{process.ProcessName}_{process.Id}";
                
                if (!_knownProcesses.Contains(processKey))
                {
                    _knownProcesses.Add(processKey);
                    
                    var accessEvent = new AccessEvent
                    {
                        Timestamp = DateTime.Now,
                        ApplicationName = process.ProcessName + ".exe",
                        ProcessId = process.Id.ToString(),
                        ResourceType = ResourceType.Microphone,
                        AccessType = AccessType.Read,
                        Details = $"Microphone access detected - Process: {process.ProcessName}, PID: {process.Id}",
                        IsSuspicious = CheckSuspiciousBehavior(process.ProcessName)
                    };

                    _accessEvents.Add(accessEvent);
                    AccessDetected?.Invoke(this, accessEvent);

                    if (accessEvent.IsSuspicious)
                    {
                        SuspiciousActivityDetected?.Invoke(this, accessEvent);
                    }
                }
            }

            // Clean up processes that are no longer running
            CleanupStaleProcesses("MIC_");
        }
        catch
        {
            // Silently handle errors to avoid spam
        }
    }

    private List<Process> GetProcessesUsingDevice(string deviceType, params string[] keywords)
    {
        var processes = new List<Process>();
        
        try
        {
            // Method 1: Check processes that might be using camera/mic based on common patterns
            var allProcesses = Process.GetProcesses();
            
            foreach (var process in allProcesses)
            {
                try
                {
                    // Check if process has handles to camera/mic related DLLs or devices
                    if (IsProcessUsingResource(process, deviceType, keywords))
                    {
                        processes.Add(process);
                    }
                }
                catch
                {
                    // Skip processes we can't access
                    continue;
                }
            }
        }
        catch
        {
            // Fallback: Use WMI to check for device usage
            try
            {
                processes.AddRange(GetProcessesUsingWMI(deviceType));
            }
            catch
            {
                // If WMI fails, use heuristic approach
                processes.AddRange(GetProcessesHeuristically(deviceType));
            }
        }

        return processes;
    }

    private bool IsProcessUsingResource(Process process, string deviceType, string[] keywords)
    {
        try
        {
            // Check process name against known applications that use camera/mic
            var processName = process.ProcessName.ToLower();
            
            // Common applications that use camera
            if (deviceType == "Camera")
            {
                var cameraApps = new[] { "chrome", "msedge", "firefox", "zoom", "teams", "skype", "discord", 
                    "obs", "obs64", "obs32", "camera", "webcam", "meet", "hangouts", "whatsapp" };
                
                foreach (var app in cameraApps)
                {
                    if (processName.Contains(app))
                        return true;
                }
            }
            
            // Common applications that use microphone
            if (deviceType == "Microphone")
            {
                var micApps = new[] { "chrome", "msedge", "firefox", "zoom", "teams", "skype", "discord",
                    "obs", "obs64", "obs32", "audacity", "meet", "hangouts", "whatsapp", "steam" };
                
                foreach (var app in micApps)
                {
                    if (processName.Contains(app))
                        return true;
                }
            }

            // Check if process has loaded DLLs related to media capture
            try
            {
                var modules = process.Modules;
                foreach (ProcessModule? module in modules)
                {
                    if (module?.ModuleName != null)
                    {
                        var moduleName = module.ModuleName.ToLower();
                        if (deviceType == "Camera" && 
                            (moduleName.Contains("mf") || moduleName.Contains("media") || 
                             moduleName.Contains("capture") || moduleName.Contains("camera")))
                        {
                            return true;
                        }
                        if (deviceType == "Microphone" && 
                            (moduleName.Contains("audio") || moduleName.Contains("mic") || 
                             moduleName.Contains("record") || moduleName.Contains("capture")))
                        {
                            return true;
                        }
                    }
                }
            }
            catch
            {
                // Can't access modules, skip
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private List<Process> GetProcessesUsingWMI(string deviceType)
    {
        var processes = new List<Process>();
        
        try
        {
            // Use WMI to query for processes using specific devices
            var query = $"SELECT * FROM Win32_Process";
            using var searcher = new ManagementObjectSearcher(query);
            
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var processId = Convert.ToInt32(obj["ProcessId"]);
                    var process = Process.GetProcessById(processId);
                    
                    if (IsProcessUsingResource(process, deviceType, Array.Empty<string>()))
                    {
                        processes.Add(process);
                    }
                }
                catch
                {
                    continue;
                }
            }
        }
        catch
        {
            // WMI query failed
        }

        return processes;
    }

    private List<Process> GetProcessesHeuristically(string deviceType)
    {
        var processes = new List<Process>();
        
        try
        {
            var allProcesses = Process.GetProcesses();
            var keywords = deviceType == "Camera" 
                ? new[] { "chrome", "msedge", "firefox", "zoom", "teams", "skype", "meet" }
                : new[] { "chrome", "msedge", "firefox", "zoom", "teams", "skype", "discord", "meet" };

            foreach (var process in allProcesses)
            {
                try
                {
                    var processName = process.ProcessName.ToLower();
                    if (keywords.Any(k => processName.Contains(k)))
                    {
                        processes.Add(process);
                    }
                }
                catch
                {
                    continue;
                }
            }
        }
        catch
        {
            // Fallback failed
        }

        return processes;
    }

    private void CleanupStaleProcesses(string prefix)
    {
        var toRemove = new List<string>();
        
        foreach (var key in _knownProcesses.Where(k => k.StartsWith(prefix)))
        {
            var parts = key.Split('_');
            if (parts.Length >= 3 && int.TryParse(parts[2], out var pid))
            {
                try
                {
                    Process.GetProcessById(pid);
                }
                catch
                {
                    // Process no longer exists
                    toRemove.Add(key);
                }
            }
        }

        foreach (var key in toRemove)
        {
            _knownProcesses.Remove(key);
        }
    }

    private bool CheckSuspiciousBehavior(string processName)
    {
        // Check for rapid access attempts
        var recentEvents = _accessEvents
            .Where(e => e.Timestamp > DateTime.Now.AddMinutes(-1))
            .Where(e => e.ApplicationName.Contains(processName, StringComparison.OrdinalIgnoreCase))
            .Count();

        return recentEvents > 10;
    }

    public List<AccessEvent> GetRecentEvents(int minutes = 60)
    {
        var cutoff = DateTime.Now.AddMinutes(-minutes);
        return _accessEvents
            .Where(e => e.Timestamp > cutoff)
            .OrderByDescending(e => e.Timestamp)
            .ToList();
    }
}
