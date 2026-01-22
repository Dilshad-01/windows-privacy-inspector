using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using WindowsPrivacyInspector.Models;

namespace WindowsPrivacyInspector.Services;

public class EventLogMonitor
{
    private readonly List<AccessEvent> _accessEvents = new();
    private EventLogWatcher? _watcher;
    private bool _isMonitoring = false;

    public event EventHandler<AccessEvent>? AccessDetected;
    public event EventHandler<AccessEvent>? SuspiciousActivityDetected;

    public void StartMonitoring()
    {
        if (_isMonitoring)
            return;

        try
        {
            // Monitor Security log for access events
            var query = new EventLogQuery("Security", PathType.LogName);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;
            _isMonitoring = true;

            Console.WriteLine("Event log monitoring started...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error starting event log monitor: {ex.Message}");
            throw;
        }
    }

    public void StopMonitoring()
    {
        if (!_isMonitoring || _watcher == null)
            return;

        _watcher.Enabled = false;
        _watcher.Dispose();
        _watcher = null;
        _isMonitoring = false;

        Console.WriteLine("Event log monitoring stopped.");
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null)
            return;

        try
        {
            var accessEvent = ParseEventRecord(e.EventRecord);
            if (accessEvent != null)
            {
                _accessEvents.Add(accessEvent);
                AccessDetected?.Invoke(this, accessEvent);

                if (accessEvent.IsSuspicious)
                {
                    SuspiciousActivityDetected?.Invoke(this, accessEvent);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing event: {ex.Message}");
        }
    }

    private AccessEvent? ParseEventRecord(EventRecord record)
    {
        try
        {
            var eventId = record.Id;
            var timeCreated = record.TimeCreated ?? DateTime.Now;
            var processName = GetProcessName(record);
            var processId = GetProcessId(record);

            // Check for camera/mic access (Event IDs may vary by Windows version)
            // These are common event IDs for resource access
            ResourceType resourceType = ResourceType.Unknown;
            AccessType accessType = AccessType.Unknown;

            // Check event description for resource access indicators
            var description = record.FormatDescription() ?? string.Empty;
            
            if (eventId == 4656 || eventId == 4663 || description.Contains("object", StringComparison.OrdinalIgnoreCase))
            {
                // Check for camera/webcam access
                if (description.Contains("camera", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("webcam", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("video capture", StringComparison.OrdinalIgnoreCase))
                {
                    resourceType = ResourceType.Camera;
                }
                // Check for microphone access
                else if (description.Contains("microphone", StringComparison.OrdinalIgnoreCase) ||
                         description.Contains("mic", StringComparison.OrdinalIgnoreCase) ||
                         description.Contains("audio capture", StringComparison.OrdinalIgnoreCase))
                {
                    resourceType = ResourceType.Microphone;
                }
                // Check for file access
                else if (description.Contains("file", StringComparison.OrdinalIgnoreCase) ||
                         description.Contains("directory", StringComparison.OrdinalIgnoreCase) ||
                         description.Contains("folder", StringComparison.OrdinalIgnoreCase))
                {
                    resourceType = ResourceType.Files;
                }
            }
            
            // Also check properties for resource indicators
            foreach (var prop in record.Properties)
            {
                var value = prop.Value?.ToString() ?? string.Empty;
                if (resourceType == ResourceType.Unknown)
                {
                    if (value.Contains("camera", StringComparison.OrdinalIgnoreCase) ||
                        value.Contains("webcam", StringComparison.OrdinalIgnoreCase))
                    {
                        resourceType = ResourceType.Camera;
                    }
                    else if (value.Contains("microphone", StringComparison.OrdinalIgnoreCase) ||
                             value.Contains("mic", StringComparison.OrdinalIgnoreCase))
                    {
                        resourceType = ResourceType.Microphone;
                    }
                    else if (value.Contains("file", StringComparison.OrdinalIgnoreCase) &&
                             (value.Contains("\\") || value.Contains("/")))
                    {
                        resourceType = ResourceType.Files;
                    }
                }
            }

            // Check for suspicious behavior
            bool isSuspicious = CheckSuspiciousBehavior(processName, timeCreated);

            return new AccessEvent
            {
                Timestamp = timeCreated.Value,
                ApplicationName = processName,
                ProcessId = processId,
                ResourceType = resourceType,
                AccessType = accessType,
                Details = record.FormatDescription() ?? string.Empty,
                IsSuspicious = isSuspicious
            };
        }
        catch
        {
            return null;
        }
    }

    private string GetProcessName(EventRecord record)
    {
        try
        {
            // Try to get process name from event description or properties
            var description = record.FormatDescription();
            if (!string.IsNullOrEmpty(description))
            {
                // Look for process name patterns in description
                var match = System.Text.RegularExpressions.Regex.Match(description, @"Process Name:\s*([^\r\n]+)");
                if (match.Success)
                    return match.Groups[1].Value.Trim();
            }

            // Try to extract from properties (properties are indexed by position)
            if (record.Properties.Count > 0)
            {
                foreach (var prop in record.Properties)
                {
                    var value = prop.Value?.ToString() ?? string.Empty;
                    if (value.Contains(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        var exeMatch = System.Text.RegularExpressions.Regex.Match(value, @"([^\\]+\.exe)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (exeMatch.Success)
                            return exeMatch.Groups[1].Value;
                    }
                }
            }

            return "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }

    private string GetProcessId(EventRecord record)
    {
        try
        {
            // Try to get process ID from event description
            var description = record.FormatDescription();
            if (!string.IsNullOrEmpty(description))
            {
                var match = System.Text.RegularExpressions.Regex.Match(description, @"Process ID:\s*(\d+)");
                if (match.Success)
                    return match.Groups[1].Value;
            }

            // Try properties
            if (record.Properties.Count > 0)
            {
                foreach (var prop in record.Properties)
                {
                    var value = prop.Value?.ToString() ?? string.Empty;
                    if (int.TryParse(value, out _))
                        return value;
                }
            }

            return record.Id.ToString();
        }
        catch
        {
            return "Unknown";
        }
    }

    private string? GetEventProperty(EventRecord record, string searchTerm)
    {
        try
        {
            var description = record.FormatDescription();
            if (!string.IsNullOrEmpty(description) && description.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
            {
                return description;
            }

            // Search in properties
            foreach (var prop in record.Properties)
            {
                var value = prop.Value?.ToString() ?? string.Empty;
                if (value.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
                {
                    return value;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private bool CheckSuspiciousBehavior(string processName, DateTime? timestamp)
    {
        if (timestamp == null)
            return false;

        // Check for rapid access attempts
        var recentEvents = _accessEvents
            .Where(e => e.Timestamp > timestamp.Value.AddMinutes(-1))
            .Where(e => e.ApplicationName == processName)
            .Count();

        return recentEvents > 10; // More than 10 access attempts in 1 minute
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

