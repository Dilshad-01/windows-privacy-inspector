using WindowsPrivacyInspector.Models;
using WindowsPrivacyInspector.Services;

namespace WindowsPrivacyInspector;

class Program
{
    private static EventLogMonitor? _eventMonitor;
    private static PrivacyManager? _privacyManager;
    private static AlertService? _alertService;

    static void Main(string[] args)
    {
        Console.WriteLine("Windows Privacy Inspector");
        Console.WriteLine("=========================");
        Console.WriteLine();

        // Check for administrator privileges
        if (!IsRunningAsAdministrator())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Warning: Administrator privileges are required for full functionality.");
            Console.ResetColor();
            Console.WriteLine();
        }

        InitializeServices();
        DisplayMenu();

        // Keep the application running
        var cancellationTokenSource = new CancellationTokenSource();
        var task = Task.Run(() => RunMainLoop(cancellationTokenSource.Token));

        Console.WriteLine("Press 'Q' to quit...");
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Q)
            {
                cancellationTokenSource.Cancel();
                break;
            }
            else if (key.Key == ConsoleKey.M)
            {
                DisplayMenu();
            }
            else if (key.Key == ConsoleKey.L)
            {
                ShowLockdownMenu();
            }
            else if (key.Key == ConsoleKey.S)
            {
                ShowStatus();
            }
            else if (key.Key == ConsoleKey.A)
            {
                ShowAlerts();
            }
        }

        Cleanup();
    }

    static void InitializeServices()
    {
        _eventMonitor = new EventLogMonitor();
        _privacyManager = new PrivacyManager();
        _alertService = new AlertService();

        // Wire up events
        _eventMonitor.AccessDetected += (sender, e) =>
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[{e.Timestamp:HH:mm:ss}] {e.ApplicationName} accessed {e.ResourceType}");
            Console.ResetColor();
        };

        _eventMonitor.SuspiciousActivityDetected += (sender, e) =>
        {
            _alertService?.ProcessEvent(e);
        };

        _alertService!.AlertTriggered += (sender, e) =>
        {
            // Alert is already displayed by AlertService
        };

        try
        {
            _eventMonitor.StartMonitoring();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error starting monitoring: {ex.Message}");
        }
    }

    static void DisplayMenu()
    {
        Console.Clear();
        Console.WriteLine("Windows Privacy Inspector");
        Console.WriteLine("=========================");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  M - Show this menu");
        Console.WriteLine("  S - Show privacy status");
        Console.WriteLine("  L - Privacy lockdown menu");
        Console.WriteLine("  A - Show recent alerts");
        Console.WriteLine("  Q - Quit");
        Console.WriteLine();
    }

    static void ShowLockdownMenu()
    {
        Console.Clear();
        Console.WriteLine("Privacy Lockdown Modes");
        Console.WriteLine("=====================");
        Console.WriteLine();
        Console.WriteLine("1. Full Lockdown (Camera + Microphone + Files)");
        Console.WriteLine("2. Camera Lockdown");
        Console.WriteLine("3. Microphone Lockdown");
        Console.WriteLine("4. File Access Lockdown");
        Console.WriteLine("5. Restore All Settings");
        Console.WriteLine("0. Back to main menu");
        Console.WriteLine();
        Console.Write("Select option: ");

        var key = Console.ReadKey();
        Console.WriteLine();

        PrivacyManager.LockdownMode? mode = key.KeyChar switch
        {
            '1' => PrivacyManager.LockdownMode.Full,
            '2' => PrivacyManager.LockdownMode.Camera,
            '3' => PrivacyManager.LockdownMode.Microphone,
            '4' => PrivacyManager.LockdownMode.Files,
            '5' => PrivacyManager.LockdownMode.None,
            _ => (PrivacyManager.LockdownMode?)null
        };

        if (mode.HasValue)
        {
            _privacyManager?.ApplyLockdown(mode.Value);
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }

        DisplayMenu();
    }

    static void ShowStatus()
    {
        Console.Clear();
        Console.WriteLine("Privacy Status");
        Console.WriteLine("==============");
        Console.WriteLine();

        var status = _privacyManager?.GetPrivacyStatus();
        if (status != null)
        {
            foreach (var item in status)
            {
                var statusText = item.Value ? "Enabled" : "Disabled";
                var color = item.Value ? ConsoleColor.Green : ConsoleColor.Red;
                Console.Write($"{item.Key}: ");
                Console.ForegroundColor = color;
                Console.WriteLine(statusText);
                Console.ResetColor();
            }
        }

        Console.WriteLine();
        Console.WriteLine("Recent Access Events (Last Hour):");
        Console.WriteLine("----------------------------------");

        var recentEvents = _eventMonitor?.GetRecentEvents(60);
        if (recentEvents != null && recentEvents.Any())
        {
            foreach (var evt in recentEvents.Take(10))
            {
                Console.WriteLine($"[{evt.Timestamp:HH:mm:ss}] {evt.ApplicationName} - {evt.ResourceType}");
            }
        }
        else
        {
            Console.WriteLine("No recent events.");
        }

        Console.WriteLine();
        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
        DisplayMenu();
    }

    static void ShowAlerts()
    {
        Console.Clear();
        Console.WriteLine("Recent Alerts");
        Console.WriteLine("=============");
        Console.WriteLine();

        var alerts = _alertService?.GetRecentAlerts(20);
        if (alerts != null && alerts.Any())
        {
            foreach (var alert in alerts)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[{alert.Timestamp:yyyy-MM-dd HH:mm:ss}]");
                Console.ResetColor();
                Console.WriteLine($"  Application: {alert.ApplicationName}");
                Console.WriteLine($"  Resource: {alert.ResourceType}");
                Console.WriteLine($"  Process ID: {alert.ProcessId}");
                Console.WriteLine();
            }
        }
        else
        {
            Console.WriteLine("No alerts.");
        }

        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
        DisplayMenu();
    }

    static void RunMainLoop(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Thread.Sleep(1000);
        }
    }

    static void Cleanup()
    {
        _eventMonitor?.StopMonitoring();
        Console.WriteLine("Application shutting down...");
    }

    static bool IsRunningAsAdministrator()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}

