# Structure reference for Microsoft Sysinternals Sysmon v11.0
Download link and official documentation: <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

All these events examples have been recorded in a Windows domain lab built thanks to the GitHub project [Windows Domain Controller Vagrant](https://github.com/rgl/windows-domain-controller-vagrant)

We also used a custom "log-all-the-things" Sysmon configuration.
```xml
<Sysmon schemaversion="4.30">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <FileCreateTime onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <ProcessTerminate onmatch="exclude" />
    <DriverLoad onmatch="exclude" />
    <ImageLoad onmatch="exclude" />
    <CreateRemoteThread onmatch="exclude" />
    <RawAccessRead onmatch="exclude" />
    <ProcessAccess onmatch="exclude" />
    <FileCreate onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
    <FileCreateStreamHash onmatch="exclude" />
    <PipeEvent onmatch="exclude" />
    <WmiEvent onmatch="exclude" />
    <DnsQuery onmatch="exclude" />
    <FileDelete onmatch="exclude" />
  </EventFiltering>
</Sysmon>
```

[Olaf Hartong](https://github.com/olafhartong) published the [sysmon-11-schema.xml](https://gist.github.com/olafhartong/ad8780b031e024d9394014b2e90f32c9) (obtained with `.\Sysmon64.exe -s`)


### Event ID 1: Process creation
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:11:58 AM
Event ID:      1
Task Category: Process Create (rule: ProcessCreate)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Process Create:
RuleName: -
UtcTime: 2020-05-07 10:11:58.238
ProcessGuid: {4f7a0cfa-deee-5eb3-ee00-000000000a00}
ProcessId: 4640
Image: C:\Windows\System32\notepad.exe
FileVersion: 10.0.17763.475 (WinBuild.160101.0800)
Description: Notepad
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: NOTEPAD.EXE
CommandLine: "C:\Windows\system32\NOTEPAD.EXE" Z:\documents\11.txt
CurrentDirectory: Z:\documents\
User: EXAMPLE\john.doe
LogonGuid: {4f7a0cfa-d965-5eb3-f083-080000000000}
LogonId: 0x883F0
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=B6D237154F2E528F0B503B58B025862D66B02B73,MD5=0E61079D3283687D2E279272966AE99D,SHA256=A92056D772260B39A876D01552496B2F8B4610A0B1E084952FE1176784E2CE77,IMPHASH=C8922BE3DCDFEB5994C9EEE7745DC22E
ParentProcessGuid: {4f7a0cfa-d967-5eb3-7a00-000000000a00}
ParentProcessId: 2724
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: C:\Windows\Explorer.EXE
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:11:58.246213000Z" />
    <EventRecordID>90968</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:11:58.238</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-deee-5eb3-ee00-000000000a00}</Data>
    <Data Name="ProcessId">4640</Data>
    <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
    <Data Name="FileVersion">10.0.17763.475 (WinBuild.160101.0800)</Data>
    <Data Name="Description">Notepad</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">NOTEPAD.EXE</Data>
    <Data Name="CommandLine">"C:\Windows\system32\NOTEPAD.EXE" Z:\documents\11.txt</Data>
    <Data Name="CurrentDirectory">Z:\documents\</Data>
    <Data Name="User">EXAMPLE\john.doe</Data>
    <Data Name="LogonGuid">{4f7a0cfa-d965-5eb3-f083-080000000000}</Data>
    <Data Name="LogonId">0x883f0</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA1=B6D237154F2E528F0B503B58B025862D66B02B73,MD5=0E61079D3283687D2E279272966AE99D,SHA256=A92056D772260B39A876D01552496B2F8B4610A0B1E084952FE1176784E2CE77,IMPHASH=C8922BE3DCDFEB5994C9EEE7745DC22E</Data>
    <Data Name="ParentProcessGuid">{4f7a0cfa-d967-5eb3-7a00-000000000a00}</Data>
    <Data Name="ParentProcessId">2724</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="ParentCommandLine">C:\Windows\Explorer.EXE</Data>
  </EventData>
</Event>
```

### Event ID 2: A process changed a file creation time
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:10:29 PM
Event ID:      2
Task Category: File creation time changed (rule: FileCreateTime)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
File creation time changed:
RuleName: -
UtcTime: 2020-05-07 11:10:29.221
ProcessGuid: {4f7a0cfa-ec34-5eb3-0a01-000000000a00}
ProcessId: 1656
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\john.doe\Desktop\log_all.xml
CreationUtcTime: 1980-01-01 13:37:00.000
PreviousCreationUtcTime: 2020-05-07 09:50:42.420
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>2</EventID>
    <Version>4</Version>
    <Level>4</Level>
    <Task>2</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:10:29.223954000Z" />
    <EventRecordID>96990</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 11:10:29.221</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-ec34-5eb3-0a01-000000000a00}</Data>
    <Data Name="ProcessId">1656</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="TargetFilename">C:\Users\john.doe\Desktop\log_all.xml</Data>
    <Data Name="CreationUtcTime">1980-01-01 13:37:00.000</Data>
    <Data Name="PreviousCreationUtcTime">2020-05-07 09:50:42.420</Data>
  </EventData>
</Event>
```

### Event ID 3: Network connection
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:13:39 PM
Event ID:      3
Task Category: Network connection detected (rule: NetworkConnect)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Network connection detected:
RuleName: -
UtcTime: 2020-05-07 11:13:38.155
ProcessGuid: {4f7a0cfa-ed5a-5eb3-1401-000000000a00}
ProcessId: 1212
Image: C:\Program Files (x86)\Internet Explorer\iexplore.exe
User: EXAMPLE\john.doe
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.0.2.15
SourceHostname: win-ws01.example.com
SourcePort: 60169
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 149.202.37.132
DestinationHostname: ip132.ip-149-202-37.eu
DestinationPort: 443
DestinationPortName: https
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>3</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>3</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:13:39.348302900Z" />
    <EventRecordID>99688</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="8" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 11:13:38.155</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-ed5a-5eb3-1401-000000000a00}</Data>
    <Data Name="ProcessId">1212</Data>
    <Data Name="Image">C:\Program Files (x86)\Internet Explorer\iexplore.exe</Data>
    <Data Name="User">EXAMPLE\john.doe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">10.0.2.15</Data>
    <Data Name="SourceHostname">win-ws01.example.com</Data>
    <Data Name="SourcePort">60169</Data>
    <Data Name="SourcePortName">-</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">149.202.37.132</Data>
    <Data Name="DestinationHostname">ip132.ip-149-202-37.eu</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationPortName">https</Data>
  </EventData>
</Event>
```

### Event ID 4: Sysmon service state changed
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 10:56:35 AM
Event ID:      4
Task Category: Sysmon service state changed
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Sysmon service state changed:
UtcTime: 2020-05-07 09:56:35.099
State: Started
Version: 11.0
SchemaVersion: 4.30
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>4</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>4</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T09:56:35.104575100Z" />
    <EventRecordID>2</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="UtcTime">2020-05-07 09:56:35.099</Data>
    <Data Name="State">Started</Data>
    <Data Name="Version">11.0</Data>
    <Data Name="SchemaVersion">4.30</Data>
  </EventData>
</Event>
```

### Event ID 5: Process terminated
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:10:39 PM
Event ID:      5
Task Category: Process terminated (rule: ProcessTerminate)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Process terminated:
RuleName: -
UtcTime: 2020-05-07 11:10:39.737
ProcessGuid: {4f7a0cfa-ec91-5eb3-0d01-000000000a00}
ProcessId: 1416
Image: C:\Windows\System32\sppsvc.exe
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>5</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>5</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:10:39.740794100Z" />
    <EventRecordID>97058</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 11:10:39.737</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-ec91-5eb3-0d01-000000000a00}</Data>
    <Data Name="ProcessId">1416</Data>
    <Data Name="Image">C:\Windows\System32\sppsvc.exe</Data>
  </EventData>
</Event>
```

### Event ID 6: Driver loaded
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:16:06 PM
Event ID:      6
Task Category: Driver loaded (rule: DriverLoad)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Driver loaded:
RuleName: -
UtcTime: 2020-05-07 11:16:06.038
ImageLoaded: C:\Windows\System32\drivers\mouhid.sys
Hashes: SHA1=3273A9917756871909CA49CF22FBBFAC3E150536,MD5=165AE5452B9155025814BAE5535E3019,SHA256=53860753238F6F953FE3B8F64B0953AA885FDCAE58C9EAD7E29EBDAABC4F96AD,IMPHASH=E1271D14C2796DEEC9FDDA717201EE3D
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>6</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>6</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:16:06.096465200Z" />
    <EventRecordID>101604</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="4744" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 11:16:06.038</Data>
    <Data Name="ImageLoaded">C:\Windows\System32\drivers\mouhid.sys</Data>
    <Data Name="Hashes">SHA1=3273A9917756871909CA49CF22FBBFAC3E150536,MD5=165AE5452B9155025814BAE5535E3019,SHA256=53860753238F6F953FE3B8F64B0953AA885FDCAE58C9EAD7E29EBDAABC4F96AD,IMPHASH=E1271D14C2796DEEC9FDDA717201EE3D</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Microsoft Windows</Data>
    <Data Name="SignatureStatus">Valid</Data>
  </EventData>
</Event>
```

### Event ID 7: Image loaded
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:00:11 AM
Event ID:      7
Task Category: Image loaded (rule: ImageLoad)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Image loaded:
RuleName: -
UtcTime: 2020-05-07 10:00:11.779
ProcessGuid: {4f7a0cfa-db65-5eb3-c000-000000000a00}
ProcessId: 948
Image: C:\Windows\System32\svchost.exe
ImageLoaded: C:\Windows\System32\twinapi.appcore.dll
FileVersion: 10.0.17763.1075 (WinBuild.160101.0800)
Description: twinapi.appcore
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: twinapi.appcore.dll
Hashes: SHA1=59894A0A3C25FFAA1651FA30C73C3A41461B6D80,MD5=3A8B12EF5BE7ED96026FFDC4F2160F23,SHA256=C88D072CD2883D000B5046E954E0089AF5C62C56F7863D1C40A6CF942FCC52AB,IMPHASH=83BC34D9E73215A3F2D5C4FA4E51622F
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>7</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>7</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:00:11.915729300Z" />
    <EventRecordID>31796</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="4744" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:00:11.779</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-db65-5eb3-c000-000000000a00}</Data>
    <Data Name="ProcessId">948</Data>
    <Data Name="Image">C:\Windows\System32\svchost.exe</Data>
    <Data Name="ImageLoaded">C:\Windows\System32\twinapi.appcore.dll</Data>
    <Data Name="FileVersion">10.0.17763.1075 (WinBuild.160101.0800)</Data>
    <Data Name="Description">twinapi.appcore</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">twinapi.appcore.dll</Data>
    <Data Name="Hashes">SHA1=59894A0A3C25FFAA1651FA30C73C3A41461B6D80,MD5=3A8B12EF5BE7ED96026FFDC4F2160F23,SHA256=C88D072CD2883D000B5046E954E0089AF5C62C56F7863D1C40A6CF942FCC52AB,IMPHASH=83BC34D9E73215A3F2D5C4FA4E51622F</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Microsoft Windows</Data>
    <Data Name="SignatureStatus">Valid</Data>
  </EventData>
</Event>
```

### Event ID 8: CreateRemoteThread
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 1:00:23 PM
Event ID:      8
Task Category: CreateRemoteThread detected (rule: CreateRemoteThread)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
CreateRemoteThread detected:
RuleName: -
UtcTime: 2020-05-07 12:00:23.525
SourceProcessGuid: {4f7a0cfa-d777-5eb3-0900-000000000a00}
SourceProcessId: 476
SourceImage: C:\Windows\System32\csrss.exe
TargetProcessGuid: {4f7a0cfa-d9f8-5eb3-a600-000000000a00}
TargetProcessId: 4536
TargetImage: C:\Windows\System32\cmd.exe
NewThreadId: 3612
StartAddress: 0x00007FFEB2233FB0
StartModule: C:\Windows\System32\KERNELBASE.dll
StartFunction: CtrlRoutine
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>8</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>8</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T12:00:23.531054800Z" />
    <EventRecordID>110546</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 12:00:23.525</Data>
    <Data Name="SourceProcessGuid">{4f7a0cfa-d777-5eb3-0900-000000000a00}</Data>
    <Data Name="SourceProcessId">476</Data>
    <Data Name="SourceImage">C:\Windows\System32\csrss.exe</Data>
    <Data Name="TargetProcessGuid">{4f7a0cfa-d9f8-5eb3-a600-000000000a00}</Data>
    <Data Name="TargetProcessId">4536</Data>
    <Data Name="TargetImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="NewThreadId">3612</Data>
    <Data Name="StartAddress">0x00007FFEB2233FB0</Data>
    <Data Name="StartModule">C:\Windows\System32\KERNELBASE.dll</Data>
    <Data Name="StartFunction">CtrlRoutine</Data>
  </EventData>
</Event>
```

### Event ID 9: RawAccessRead
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:18:50 AM
Event ID:      9
Task Category: RawAccessRead detected (rule: RawAccessRead)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
RawAccessRead detected:
RuleName: -
UtcTime: 2020-05-07 10:18:50.938
ProcessGuid: {4f7a0cfa-e08a-5eb3-fe00-000000000a00}
ProcessId: 3968
Image: C:\Windows\System32\svchost.exe
Device: \Device\HarddiskVolume1
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>9</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>9</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:18:50.944336800Z" />
    <EventRecordID>92380</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:18:50.938</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-e08a-5eb3-fe00-000000000a00}</Data>
    <Data Name="ProcessId">3968</Data>
    <Data Name="Image">C:\Windows\System32\svchost.exe</Data>
    <Data Name="Device">\Device\HarddiskVolume1</Data>
  </EventData>
</Event>
```

### Event ID 10: ProcessAccess
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:07:16 AM
Event ID:      10
Task Category: Process accessed (rule: ProcessAccess)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Process accessed:
RuleName: -
UtcTime: 2020-05-07 10:07:16.201
SourceProcessGUID: {4f7a0cfa-d967-5eb3-7a00-000000000a00}
SourceProcessId: 2724
SourceThreadId: 3408
SourceImage: C:\Windows\Explorer.EXE
TargetProcessGUID: {4f7a0cfa-d9f8-5eb3-a600-000000000a00}
TargetProcessId: 4536
TargetImage: C:\Windows\system32\cmd.exe
GrantedAccess: 0x2000
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9fc14|C:\Windows\System32\KERNELBASE.dll+20d5e|C:\Windows\system32\twinui.dll+30ee6|C:\Windows\SYSTEM32\ntdll.dll+4e719|C:\Windows\SYSTEM32\ntdll.dll+505c4|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+6a261
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>10</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>10</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:07:16.204629400Z" />
    <EventRecordID>80463</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:07:16.201</Data>
    <Data Name="SourceProcessGUID">{4f7a0cfa-d967-5eb3-7a00-000000000a00}</Data>
    <Data Name="SourceProcessId">2724</Data>
    <Data Name="SourceThreadId">3408</Data>
    <Data Name="SourceImage">C:\Windows\Explorer.EXE</Data>
    <Data Name="TargetProcessGUID">{4f7a0cfa-d9f8-5eb3-a600-000000000a00}</Data>
    <Data Name="TargetProcessId">4536</Data>
    <Data Name="TargetImage">C:\Windows\system32\cmd.exe</Data>
    <Data Name="GrantedAccess">0x2000</Data>
    <Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9fc14|C:\Windows\System32\KERNELBASE.dll+20d5e|C:\Windows\system32\twinui.dll+30ee6|C:\Windows\SYSTEM32\ntdll.dll+4e719|C:\Windows\SYSTEM32\ntdll.dll+505c4|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+6a261</Data>
  </EventData>
</Event>
```

### Event ID 11: FileCreate
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:11:20 AM
Event ID:      11
Task Category: File created (rule: FileCreate)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
File created:
RuleName: -
UtcTime: 2020-05-07 10:11:20.591
ProcessGuid: {4f7a0cfa-db8e-5eb3-c500-000000000a00}
ProcessId: 2040
Image: C:\Windows\system32\mmc.exe
TargetFilename: C:\Users\john.doe\AppData\Local\Temp\tmpD803.xml
CreationUtcTime: 2020-05-07 09:58:23.982
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:11:20.599614600Z" />
    <EventRecordID>90706</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:11:20.591</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-db8e-5eb3-c500-000000000a00}</Data>
    <Data Name="ProcessId">2040</Data>
    <Data Name="Image">C:\Windows\system32\mmc.exe</Data>
    <Data Name="TargetFilename">C:\Users\john.doe\AppData\Local\Temp\tmpD803.xml</Data>
    <Data Name="CreationUtcTime">2020-05-07 09:58:23.982</Data>
  </EventData>
</Event>
```

### Event ID 12: RegistryEvent (Object create and delete)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:04:37 AM
Event ID:      12
Task Category: Registry object added or deleted (rule: RegistryEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Registry object added or deleted:
RuleName: -
EventType: DeleteValue
UtcTime: 2020-05-07 10:04:37.701
ProcessGuid: {4f7a0cfa-db65-5eb3-c000-000000000a00}
ProcessId: 948
Image: C:\Windows\system32\svchost.exe
TargetObject: HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Deployment\Package\*\S-1-5-21-4119188036-1989734758-402085768-1105\{63C44A58-736D-4C57-AAB4-76E2AE8B5EA9}\116
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>12</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>12</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:04:37.703548100Z" />
    <EventRecordID>67046</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">DeleteValue</Data>
    <Data Name="UtcTime">2020-05-07 10:04:37.701</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-db65-5eb3-c000-000000000a00}</Data>
    <Data Name="ProcessId">948</Data>
    <Data Name="Image">C:\Windows\system32\svchost.exe</Data>
    <Data Name="TargetObject">HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Deployment\Package\*\S-1-5-21-4119188036-1989734758-402085768-1105\{63C44A58-736D-4C57-AAB4-76E2AE8B5EA9}\116</Data>
  </EventData>
</Event>
```

### Event ID 13: RegistryEvent (Value Set)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:04:37 AM
Event ID:      13
Task Category: Registry value set (rule: RegistryEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Registry value set:
RuleName: -
EventType: SetValue
UtcTime: 2020-05-07 10:04:37.701
ProcessGuid: {4f7a0cfa-db65-5eb3-c000-000000000a00}
ProcessId: 948
Image: C:\Windows\system32\svchost.exe
TargetObject: HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Deployment\Package\*\S-1-5-21-4119188036-1989734758-402085768-1105\{63C44A58-736D-4C57-AAB4-76E2AE8B5EA9}\Count
Details: DWORD (0x00000000)
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>13</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>13</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:04:37.703580500Z" />
    <EventRecordID>67047</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">SetValue</Data>
    <Data Name="UtcTime">2020-05-07 10:04:37.701</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-db65-5eb3-c000-000000000a00}</Data>
    <Data Name="ProcessId">948</Data>
    <Data Name="Image">C:\Windows\system32\svchost.exe</Data>
    <Data Name="TargetObject">HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Deployment\Package\*\S-1-5-21-4119188036-1989734758-402085768-1105\{63C44A58-736D-4C57-AAB4-76E2AE8B5EA9}\Count</Data>
    <Data Name="Details">DWORD (0x00000000)</Data>
  </EventData>
</Event>
```

### Event ID 14: RegistryEvent (Key and Value Rename)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:33:36 PM
Event ID:      14
Task Category: Registry object renamed (rule: RegistryEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Registry object renamed:
RuleName: -
EventType: RenameKey
UtcTime: 2020-05-07 11:33:36.309
ProcessGuid: {4f7a0cfa-f1f5-5eb3-2201-000000000a00}
ProcessId: 1928
Image: C:\Windows\regedit.exe
TargetObject: HKU\S-1-5-19\System\CurrentControlSet\Control\Network\NetworkLocationWizard\test
NewName: HKU\S-1-5-19\System\CurrentControlSet\Control\Network\NetworkLocationWizard\hello
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>14</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>14</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:33:36.321001700Z" />
    <EventRecordID>103498</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">RenameKey</Data>
    <Data Name="UtcTime">2020-05-07 11:33:36.309</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-f1f5-5eb3-2201-000000000a00}</Data>
    <Data Name="ProcessId">1928</Data>
    <Data Name="Image">C:\Windows\regedit.exe</Data>
    <Data Name="TargetObject">HKU\S-1-5-19\System\CurrentControlSet\Control\Network\NetworkLocationWizard\test</Data>
    <Data Name="NewName">HKU\S-1-5-19\System\CurrentControlSet\Control\Network\NetworkLocationWizard\hello</Data>
  </EventData>
</Event>
```

### Event ID 15: FileCreateStreamHash
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 1:51:27 PM
Event ID:      15
Task Category: File stream created (rule: FileCreateStreamHash)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
File stream created:
RuleName: -
UtcTime: 2020-05-07 12:51:27.049
ProcessGuid: {4f7a0cfa-0432-5eb4-8001-000000000a00}
ProcessId: 2000
Image: C:\Program Files\internet explorer\iexplore.exe
TargetFilename: C:\Users\john.doe\AppData\Local\Microsoft\Windows\INetCache\IE\0LGNF25C\7z1900-src.7z
CreationUtcTime: 2020-05-07 12:51:26.973
Hash: SHA1=1632462EF90D158B10081DC545E4781DAFB2CBED,MD5=55EB2C0A1D897E5E3A9A84A25590B79F,SHA256=9BA70A5E8485CF9061B30A2A84FE741DE5AEB8DD271AAB8889DA0E9B3BF1868E,IMPHASH=00000000000000000000000000000000
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>15</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>15</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T12:51:27.070520000Z" />
    <EventRecordID>128970</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 12:51:27.049</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-0432-5eb4-8001-000000000a00}</Data>
    <Data Name="ProcessId">2000</Data>
    <Data Name="Image">C:\Program Files\internet explorer\iexplore.exe</Data>
    <Data Name="TargetFilename">C:\Users\john.doe\AppData\Local\Microsoft\Windows\INetCache\IE\0LGNF25C\7z1900-src.7z</Data>
    <Data Name="CreationUtcTime">2020-05-07 12:51:26.973</Data>
    <Data Name="Hash">SHA1=1632462EF90D158B10081DC545E4781DAFB2CBED,MD5=55EB2C0A1D897E5E3A9A84A25590B79F,SHA256=9BA70A5E8485CF9061B30A2A84FE741DE5AEB8DD271AAB8889DA0E9B3BF1868E,IMPHASH=00000000000000000000000000000000</Data>
  </EventData>
</Event>
```

### Event ID 16: Sysmon config state changed
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 10:56:34 AM
Event ID:      16
Task Category: Sysmon config state changed
Level:         Information
Keywords:      
User:          EXAMPLE\john.doe
Computer:      win-ws01.example.com
Description:
Sysmon config state changed:
UtcTime: 2020-05-07 09:56:34.176
Configuration: C:\Users\john.doe\Desktop\log_all.xml
ConfigurationFileHash: SHA1=0A2D72963AD33C481527BCFB41BEDB47B733BB88
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>16</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>16</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T09:56:34.185370000Z" />
    <EventRecordID>1</EventRecordID>
    <Correlation />
    <Execution ProcessID="3788" ThreadID="4612" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-21-4119188036-1989734758-402085768-1105" />
  </System>
  <EventData>
    <Data Name="UtcTime">2020-05-07 09:56:34.176</Data>
    <Data Name="Configuration">C:\Users\john.doe\Desktop\log_all.xml</Data>
    <Data Name="ConfigurationFileHash">SHA1=0A2D72963AD33C481527BCFB41BEDB47B733BB88</Data>
  </EventData>
</Event>
```

### Event ID 17: PipeEvent (Pipe Created)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 12:08:36 PM
Event ID:      17
Task Category: Pipe Created (rule: PipeEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Pipe Created:
RuleName: -
EventType: CreatePipe
UtcTime: 2020-05-07 11:08:36.815
ProcessGuid: {4f7a0cfa-ec34-5eb3-0a01-000000000a00}
ProcessId: 1656
PipeName: \PSHost.132333233165156749.1656.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>17</EventID>
    <Version>1</Version>
    <Level>4</Level>
    <Task>17</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T11:08:36.825417900Z" />
    <EventRecordID>94916</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">CreatePipe</Data>
    <Data Name="UtcTime">2020-05-07 11:08:36.815</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-ec34-5eb3-0a01-000000000a00}</Data>
    <Data Name="ProcessId">1656</Data>
    <Data Name="PipeName">\PSHost.132333233165156749.1656.DefaultAppDomain.powershell</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  </EventData>
</Event>
```

### Event ID 18: PipeEvent (Pipe Connected)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:07:14 AM
Event ID:      18
Task Category: Pipe Connected (rule: PipeEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Pipe Connected:
RuleName: -
EventType: ConnectPipe
UtcTime: 2020-05-07 10:07:14.483
ProcessGuid: {4f7a0cfa-d778-5eb3-2000-000000000a00}
ProcessId: 1584
PipeName: \VBoxTrayIPC-john.doe
Image: C:\Windows\System32\VBoxService.exe
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>18</EventID>
    <Version>1</Version>
    <Level>4</Level>
    <Task>18</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:07:14.498673700Z" />
    <EventRecordID>80438</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">ConnectPipe</Data>
    <Data Name="UtcTime">2020-05-07 10:07:14.483</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-d778-5eb3-2000-000000000a00}</Data>
    <Data Name="ProcessId">1584</Data>
    <Data Name="PipeName">\VBoxTrayIPC-john.doe</Data>
    <Data Name="Image">C:\Windows\System32\VBoxService.exe</Data>
  </EventData>
</Event>
```

### Event ID 19: WmiEvent (WmiEventFilter activity detected)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 1:18:50 PM
Event ID:      19
Task Category: WmiEventFilter activity detected (rule: WmiEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
WmiEventFilter activity detected:
RuleName: -
EventType: WmiFilterEvent
UtcTime: 2020-05-07 12:18:50.648
Operation: Created
User: EXAMPLE\john.doe
EventNamespace:  "root\\cimv2"
Name:  "test"
Query:  "select * from __instanceModificationEvent"
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>19</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>19</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T12:18:50.657456200Z" />
    <EventRecordID>111386</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="696" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">WmiFilterEvent</Data>
    <Data Name="UtcTime">2020-05-07 12:18:50.648</Data>
    <Data Name="Operation">Created</Data>
    <Data Name="User">EXAMPLE\john.doe</Data>
    <Data Name="EventNamespace"> "root\\cimv2"</Data>
    <Data Name="Name"> "test"</Data>
    <Data Name="Query"> "select * from __instanceModificationEvent"</Data>
  </EventData>
</Event>
```

### Event ID 20: WmiEvent (WmiEventConsumer activity detected)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 1:27:16 PM
Event ID:      20
Task Category: WmiEventConsumer activity detected (rule: WmiEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
WmiEventConsumer activity detected:
RuleName: -
EventType: WmiConsumerEvent
UtcTime: 2020-05-07 12:27:16.113
Operation: Created
User: S-1-5-21-4119188036-1989734758-0-0
Name:  "ServiceConsumer"
Type: Log File
Destination:  "C:\\Scripts\\Log.log"
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>20</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>20</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T12:27:16.259355800Z" />
    <EventRecordID>116617</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="5596" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">WmiConsumerEvent</Data>
    <Data Name="UtcTime">2020-05-07 12:27:16.113</Data>
    <Data Name="Operation">Created</Data>
    <Data Name="User">S-1-5-21-4119188036-1989734758-0-0</Data>
    <Data Name="Name"> "ServiceConsumer"</Data>
    <Data Name="Type">Log File</Data>
    <Data Name="Destination"> "C:\\Scripts\\Log.log"</Data>
  </EventData>
</Event>
```

### Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 1:45:59 PM
Event ID:      21
Task Category: WmiEventConsumerToFilter activity detected (rule: WmiEvent)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
WmiEventConsumerToFilter activity detected:
RuleName: -
EventType: WmiBindingEvent
UtcTime: 2020-05-07 12:45:59.263
Operation: Created
User: EXAMPLE\john.doe
Consumer:  "\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"USBConsumer\""
Filter:  "\\\\.\\root\\subscription:LogFileEventConsumer.Name=\"ServiceConsumer\""
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>21</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>21</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T12:45:59.263475800Z" />
    <EventRecordID>121141</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="5972" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">WmiBindingEvent</Data>
    <Data Name="UtcTime">2020-05-07 12:45:59.263</Data>
    <Data Name="Operation">Created</Data>
    <Data Name="User">EXAMPLE\john.doe</Data>
    <Data Name="Consumer"> "\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"USBConsumer\""</Data>
    <Data Name="Filter"> "\\\\.\\root\\subscription:LogFileEventConsumer.Name=\"ServiceConsumer\""</Data>
  </EventData>
</Event>
```

### Event ID 22: DNSEvent (DNS query)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:13:58 AM
Event ID:      22
Task Category: Dns query (rule: DnsQuery)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
Dns query:
RuleName: -
UtcTime: 2020-05-07 10:13:57.441
ProcessGuid: {4f7a0cfa-db69-5eb3-c100-000000000a00}
ProcessId: 3376
QueryName: www.perdu.com
QueryStatus: 0
QueryResults: ::ffff:208.97.177.124;
Image: C:\Program Files (x86)\Internet Explorer\iexplore.exe
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>22</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>22</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:13:58.410832000Z" />
    <EventRecordID>91917</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3784" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:13:57.441</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-db69-5eb3-c100-000000000a00}</Data>
    <Data Name="ProcessId">3376</Data>
    <Data Name="QueryName">www.perdu.com</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">::ffff:208.97.177.124;</Data>
    <Data Name="Image">C:\Program Files (x86)\Internet Explorer\iexplore.exe</Data>
  </EventData>
</Event>
```

### Event ID 23: FileDelete (A file delete was detected)
```yaml
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Date:          5/7/2020 11:04:37 AM
Event ID:      23
Task Category: File Delete (rule: FileDelete)
Level:         Information
Keywords:      
User:          SYSTEM
Computer:      win-ws01.example.com
Description:
File Delete:
RuleName: -
UtcTime: 2020-05-07 10:04:37.717
ProcessGuid: {4f7a0cfa-d777-5eb3-1900-000000000a00}
ProcessId: 1056
User: NT AUTHORITY\SYSTEM
Image: C:\Windows\System32\svchost.exe
TargetFilename: C:\Windows\Prefetch\SEARCHFILTERHOST.EXE-AA7A1FDD.pf
Hashes: SHA1=826448869D737DFBF31D8215BD46658B276182A3,MD5=E6150EE26D55C66E7A5221001C08A472,SHA256=3E80CE60985D75ED817D6BA115113A2C3331A6EC55E3EBFFA59FB69834D70533,IMPHASH=00000000000000000000000000000000
IsExecutable: false
Archived: true
```
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>23</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>23</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2020-05-07T10:04:37.719548500Z" />
    <EventRecordID>67072</EventRecordID>
    <Correlation />
    <Execution ProcessID="3648" ThreadID="3444" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>win-ws01.example.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2020-05-07 10:04:37.717</Data>
    <Data Name="ProcessGuid">{4f7a0cfa-d777-5eb3-1900-000000000a00}</Data>
    <Data Name="ProcessId">1056</Data>
    <Data Name="User">NT AUTHORITY\SYSTEM</Data>
    <Data Name="Image">C:\Windows\System32\svchost.exe</Data>
    <Data Name="TargetFilename">C:\Windows\Prefetch\SEARCHFILTERHOST.EXE-AA7A1FDD.pf</Data>
    <Data Name="Hashes">SHA1=826448869D737DFBF31D8215BD46658B276182A3,MD5=E6150EE26D55C66E7A5221001C08A472,SHA256=3E80CE60985D75ED817D6BA115113A2C3331A6EC55E3EBFFA59FB69834D70533,IMPHASH=00000000000000000000000000000000</Data>
    <Data Name="IsExecutable">false</Data>
    <Data Name="Archived">true</Data>
  </EventData>
</Event>
```
