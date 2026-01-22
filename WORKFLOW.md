# Windows Privacy Inspector - Workflow Diagram

## System Architecture Flow

```mermaid
graph TB
    Start([Application Start]) --> CheckAdmin{Check Admin<br/>Privileges}
    CheckAdmin -->|Yes| Init[Initialize Services]
    CheckAdmin -->|No| Warning[Show Warning]
    Warning --> Init
    
    Init --> EventMonitor[EventLogMonitor]
    Init --> PrivacyMgr[PrivacyManager]
    Init --> AlertSvc[AlertService]
    
    EventMonitor --> StartMonitoring[Start Event Log<br/>Monitoring]
    StartMonitoring --> EventWatcher[Windows Event Log<br/>Watcher]
    
    EventWatcher -->|New Event| ParseEvent[Parse Event Record]
    ParseEvent --> DetectResource{Detect Resource<br/>Type}
    
    DetectResource -->|Camera| CameraEvent[Camera Access Event]
    DetectResource -->|Microphone| MicEvent[Microphone Access Event]
    DetectResource -->|Files| FileEvent[File Access Event]
    DetectResource -->|Unknown| UnknownEvent[Unknown Event]
    
    CameraEvent --> CheckSuspicious{Check Suspicious<br/>Behavior}
    MicEvent --> CheckSuspicious
    FileEvent --> CheckSuspicious
    UnknownEvent --> CheckSuspicious
    
    CheckSuspicious -->|Suspicious| AlertSvc
    CheckSuspicious -->|Normal| DisplayEvent[Display Event]
    
    AlertSvc --> ProcessAlert[Process Alert]
    ProcessAlert --> DisplayAlert[Display Alert<br/>to User]
    ProcessAlert --> StoreAlert[Store Alert]
    
    DisplayEvent --> UserMenu[User Menu]
    DisplayAlert --> UserMenu
    
    UserMenu -->|M| ShowMenu[Show Menu]
    UserMenu -->|S| ShowStatus[Show Privacy Status]
    UserMenu -->|L| LockdownMenu[Privacy Lockdown Menu]
    UserMenu -->|A| ShowAlerts[Show Recent Alerts]
    UserMenu -->|Q| Quit[Quit Application]
    
    LockdownMenu --> SelectMode{Select Lockdown<br/>Mode}
    SelectMode -->|Full| FullLockdown[Disable Camera<br/>+ Microphone<br/>+ Files]
    SelectMode -->|Camera| CameraLockdown[Disable Camera]
    SelectMode -->|Microphone| MicLockdown[Disable Microphone]
    SelectMode -->|Files| FileLockdown[Restrict File Access]
    SelectMode -->|Restore| RestoreSettings[Restore All Settings]
    
    FullLockdown --> PowerShell[Execute PowerShell<br/>Scripts]
    CameraLockdown --> PowerShell
    MicLockdown --> PowerShell
    FileLockdown --> PowerShell
    RestoreSettings --> PowerShell
    
    PowerShell --> Registry[Modify Windows<br/>Registry]
    Registry --> Confirm[Confirm Changes]
    Confirm --> UserMenu
    
    ShowStatus --> GetStatus[Get Privacy Status]
    GetStatus --> CheckRegistry[Check Registry<br/>Settings]
    CheckRegistry --> DisplayStatus[Display Status]
    DisplayStatus --> UserMenu
    
    ShowAlerts --> GetAlerts[Get Recent Alerts]
    GetAlerts --> DisplayAlerts[Display Alert List]
    DisplayAlerts --> UserMenu
    
    Quit --> StopMonitoring[Stop Event Monitoring]
    StopMonitoring --> Cleanup[Cleanup Resources]
    Cleanup --> End([Application End])
```

## Event Monitoring Flow

```mermaid
sequenceDiagram
    participant User
    participant App as Main Application
    participant Monitor as EventLogMonitor
    participant EventLog as Windows Event Log
    participant Alert as AlertService
    participant Privacy as PrivacyManager
    
    User->>App: Start Application
    App->>Monitor: Initialize EventLogMonitor
    Monitor->>EventLog: Subscribe to Security Log
    EventLog-->>Monitor: Event Record Written
    
    Monitor->>Monitor: Parse Event Record
    Monitor->>Monitor: Detect Resource Type
    Monitor->>Monitor: Check Suspicious Behavior
    
    alt Suspicious Activity Detected
        Monitor->>Alert: Trigger Alert
        Alert->>Alert: Process Alert
        Alert->>User: Display Alert Notification
    else Normal Activity
        Monitor->>User: Display Event Info
    end
    
    User->>App: Request Privacy Status
    App->>Privacy: Get Privacy Status
    Privacy->>Privacy: Check Registry Settings
    Privacy-->>App: Return Status
    App->>User: Display Status
    
    User->>App: Request Lockdown
    App->>Privacy: Apply Lockdown Mode
    Privacy->>Privacy: Execute PowerShell Scripts
    Privacy->>Privacy: Modify Registry
    Privacy-->>App: Confirm Changes
    App->>User: Display Confirmation
```

## Privacy Lockdown Flow

```mermaid
flowchart TD
    Start([User Selects Lockdown Mode]) --> Select{Select Mode}
    
    Select -->|Full| Full[Full Lockdown]
    Select -->|Camera| Camera[Camera Only]
    Select -->|Microphone| Mic[Microphone Only]
    Select -->|Files| Files[Files Only]
    Select -->|Restore| Restore[Restore All]
    
    Full --> DisableCam[Disable Camera<br/>via Registry]
    Full --> DisableMic[Disable Microphone<br/>via Registry]
    Full --> RestrictFiles[Restrict File Access]
    
    Camera --> DisableCam
    Mic --> DisableMic
    Files --> RestrictFiles
    
    DisableCam --> PS1[Execute PowerShell<br/>PrivacyLockdown.ps1]
    DisableMic --> PS1
    RestrictFiles --> PS1
    
    PS1 --> RegPath1[HKCU:\SOFTWARE\...\webcam<br/>Value = Deny]
    PS1 --> RegPath2[HKCU:\SOFTWARE\...\microphone<br/>Value = Deny]
    PS1 --> RegPath3[File Access Restrictions]
    
    RegPath1 --> Verify[Verify Changes]
    RegPath2 --> Verify
    RegPath3 --> Verify
    
    Verify --> Success{Success?}
    Success -->|Yes| Confirm[Display Success Message]
    Success -->|No| Error[Display Error Message]
    
    Restore --> RestorePS[Execute PowerShell<br/>Restore Script]
    RestorePS --> RestoreReg[Set Registry Values<br/>to Allow]
    RestoreReg --> Verify
    
    Confirm --> End([Return to Menu])
    Error --> End
```

## Alert Detection Flow

```mermaid
graph LR
    Event[Access Event Detected] --> Check1{Unknown<br/>Application?}
    Check1 -->|Yes| Alert[Trigger Alert]
    Check1 -->|No| Check2{Rapid Access<br/>Attempts?}
    
    Check2 -->|>10 in 1 min| Alert
    Check2 -->|No| Check3{Background<br/>Access?}
    
    Check3 -->|Yes| Alert
    Check3 -->|No| Normal[Log Normal Event]
    
    Alert --> Analyze[Analyze Event Details]
    Analyze --> Store[Store in Alert List]
    Store --> Notify[Notify User]
    Notify --> Display[Display Alert UI]
    
    Normal --> Log[Log to Event History]
```

## Component Interaction Diagram

```mermaid
graph TB
    subgraph "Main Application"
        Program[Program.cs<br/>Entry Point]
        Menu[User Menu System]
    end
    
    subgraph "Services Layer"
        EventMonitor[EventLogMonitor<br/>- Monitor Events<br/>- Parse Events<br/>- Detect Resources]
        PrivacyMgr[PrivacyManager<br/>- Apply Lockdown<br/>- Check Status<br/>- Execute Scripts]
        AlertSvc[AlertService<br/>- Process Alerts<br/>- Store Alerts<br/>- Display Alerts]
    end
    
    subgraph "Data Models"
        AccessEvent[AccessEvent<br/>- Timestamp<br/>- Application<br/>- Resource Type<br/>- Suspicious Flag]
    end
    
    subgraph "External Systems"
        EventLog[Windows Event Log<br/>Security Log]
        Registry[Windows Registry<br/>Privacy Settings]
        PowerShell[PowerShell Scripts<br/>- MonitorEvents.ps1<br/>- PrivacyLockdown.ps1<br/>- GetPrivacyStatus.ps1]
    end
    
    Program --> Menu
    Menu --> EventMonitor
    Menu --> PrivacyMgr
    Menu --> AlertSvc
    
    EventMonitor --> AccessEvent
    EventMonitor --> AlertSvc
    EventMonitor --> EventLog
    
    PrivacyMgr --> Registry
    PrivacyMgr --> PowerShell
    
    AlertSvc --> AccessEvent
    
    EventLog -->|Events| EventMonitor
    Registry -->|Settings| PrivacyMgr
    PowerShell -->|Execute| Registry
```

## Data Flow Diagram

```mermaid
flowchart TD
    Windows[Windows System] -->|Generate Events| EventLog[Event Log]
    EventLog -->|Read Events| Monitor[EventLogMonitor]
    
    Monitor -->|Parse| Event[AccessEvent Object]
    Event -->|Check Rules| AlertService[AlertService]
    
    AlertService -->|Suspicious?| Alert[Alert Object]
    AlertService -->|Normal| History[Event History]
    
    Event -->|Display| UI[User Interface]
    Alert -->|Display| UI
    
    User[User Input] -->|Commands| UI
    UI -->|Lockdown Request| PrivacyMgr[PrivacyManager]
    
    PrivacyMgr -->|Execute| PS[PowerShell Scripts]
    PS -->|Modify| Registry[Windows Registry]
    Registry -->|Apply| Windows
    
    PrivacyMgr -->|Check Status| Registry
    Registry -->|Return Status| PrivacyMgr
    PrivacyMgr -->|Display| UI
```
