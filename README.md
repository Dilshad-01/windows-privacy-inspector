# Windows Privacy Inspector

A comprehensive Windows privacy monitoring tool that helps you track and control which applications access your sensitive resources like camera, microphone, and files.

**Author:** Mohamed Dilshad KP

## Features

- **Resource Access Monitoring**: Shows which apps access camera, microphone, and files in real-time
- **Suspicious Behavior Alerts**: Monitors and alerts on suspicious background behavior
- **One-Click Privacy Lockdown**: Provides quick privacy lockdown modes to disable access to sensitive resources

## Technology Stack

- **Windows Event Logs**: Monitors system events for resource access
- **PowerShell**: Scripts for event log analysis and system configuration
- **C#**: Main application logic and user interface

## Requirements

- Windows 10/11
- .NET 6.0 or later
- Administrator privileges (for event log access and privacy settings)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Dilshad-01/windows-privacy-inspector.git
cd windows-privacy-inspector
```

2. Build the project:
```bash
dotnet build
```

3. Run the application (requires administrator privileges):
```bash
dotnet run --project WindowsPrivacyInspector
```

## Usage

### Monitor Resource Access
The tool continuously monitors Windows Event Logs to detect when applications access:
- Camera
- Microphone
- File system

### Privacy Lockdown Modes
Use one-click lockdown modes to quickly disable access:
- **Full Lockdown**: Disables camera, microphone, and file access for all apps
- **Camera Lockdown**: Disables only camera access
- **Microphone Lockdown**: Disables only microphone access
- **File Access Lockdown**: Restricts file system access

### Alerts
The application will alert you when:
- Unknown applications attempt to access sensitive resources
- Multiple rapid access attempts are detected
- Background processes access resources without user interaction

## Workflow Diagram

For a detailed visual representation of the system architecture, data flow, and component interactions, see [WORKFLOW.md](WORKFLOW.md).

The workflow diagrams include:
- System Architecture Flow
- Event Monitoring Flow (Sequence Diagram)
- Privacy Lockdown Flow
- Alert Detection Flow
- Component Interaction Diagram
- Data Flow Diagram

## Project Structure

```
WindowsPrivacyInspector/
├── WindowsPrivacyInspector/
│   ├── Program.cs              # Main application entry point
│   ├── Services/               # Core service classes
│   │   ├── EventLogMonitor.cs  # Windows Event Log monitoring
│   │   ├── PrivacyManager.cs   # Privacy settings management
│   │   └── AlertService.cs     # Alert generation and handling
│   ├── Models/                 # Data models
│   │   └── AccessEvent.cs      # Event data structures
│   └── WindowsPrivacyInspector.csproj
├── Scripts/
│   ├── MonitorEvents.ps1       # PowerShell event monitoring
│   ├── PrivacyLockdown.ps1     # Privacy lockdown scripts
│   └── GetPrivacyStatus.ps1    # Privacy status checking
├── README.md
├── WORKFLOW.md                 # Workflow diagrams
├── LICENSE
└── .gitignore
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool requires administrator privileges to function properly. Use responsibly and ensure you understand the implications of modifying system privacy settings.

---

**Author:** Mohamed Dilshad KP  
**Repository:** [https://github.com/Dilshad-01/windows-privacy-inspector](https://github.com/Dilshad-01/windows-privacy-inspector) 
