using WindowsPrivacyInspector.Models;

namespace WindowsPrivacyInspector.Services;

public class AlertService
{
    private readonly List<AccessEvent> _alerts = new();

    public event EventHandler<AccessEvent>? AlertTriggered;

    public void ProcessEvent(AccessEvent accessEvent)
    {
        if (ShouldAlert(accessEvent))
        {
            _alerts.Add(accessEvent);
            AlertTriggered?.Invoke(this, accessEvent);
            DisplayAlert(accessEvent);
        }
    }

    private bool ShouldAlert(AccessEvent accessEvent)
    {
        // Alert on suspicious activity
        if (accessEvent.IsSuspicious)
            return true;

        // Alert on unknown applications
        if (IsUnknownApplication(accessEvent.ApplicationName))
            return true;

        // Alert on background access without user interaction
        if (IsBackgroundAccess(accessEvent))
            return true;

        return false;
    }

    private bool IsUnknownApplication(string applicationName)
    {
        // List of known trusted applications (can be expanded)
        var trustedApps = new[]
        {
            "explorer.exe",
            "dwm.exe",
            "winlogon.exe",
            "csrss.exe",
            "svchost.exe"
        };

        return !trustedApps.Contains(applicationName.ToLower());
    }

    private bool IsBackgroundAccess(AccessEvent accessEvent)
    {
        // Simplified check - in production, this would check if user is actively using the app
        // For now, we'll consider it suspicious if it's not a common system process
        var systemProcesses = new[]
        {
            "explorer.exe",
            "dwm.exe"
        };

        return !systemProcesses.Contains(accessEvent.ApplicationName.ToLower());
    }

    private void DisplayAlert(AccessEvent accessEvent)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n[ALERT] Suspicious Activity Detected!");
        Console.ResetColor();
        Console.WriteLine($"Time: {accessEvent.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"Application: {accessEvent.ApplicationName}");
        Console.WriteLine($"Resource: {accessEvent.ResourceType}");
        Console.WriteLine($"Process ID: {accessEvent.ProcessId}");
        Console.WriteLine($"Details: {accessEvent.Details}");
        Console.WriteLine();
    }

    public List<AccessEvent> GetRecentAlerts(int count = 10)
    {
        return _alerts
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToList();
    }

    public void ClearAlerts()
    {
        _alerts.Clear();
    }
}

