namespace WindowsPrivacyInspector.Models;

public class AccessEvent
{
    public DateTime Timestamp { get; set; }
    public string ApplicationName { get; set; } = string.Empty;
    public string ProcessId { get; set; } = string.Empty;
    public ResourceType ResourceType { get; set; }
    public AccessType AccessType { get; set; }
    public string Details { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public enum ResourceType
{
    Camera,
    Microphone,
    Files,
    Location,
    Unknown
}

public enum AccessType
{
    Read,
    Write,
    Execute,
    Unknown
}

