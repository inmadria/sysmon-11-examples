# Sysmon 11 events mapping with CAR Data Model

## Context
[CAR (Cyber Analytics Repository)](https://github.com/mitre-attack/car) provides to *Threat Hunters* a generic model useful for investigations. It is composed of:
- **Analytics** (detection rules)
- **Data Model** (atomic elements formalization) 
- **Sensors** (tools that logs these elements)

Microsoft Sysinternals Sysmon is one of these sensors. We mapped its attributes with those of CAR data model.

Please note that we only mapped fields that are present in logs without needing any transformation. For example, the field `fqdn` is present as `Computer` but the field `hostname` could be extracted from this value. Same thing for `file_name`, `exe`, `hive`, *etc*. Thus we provide for each event type a table of "Fields that require a transformation".

## Events mapping

### Event ID 1: Process creation
#### CAR `process create`
|Sysmon|CAR|
|---|---|
|CommandLine|command_line|
|Computer|fqdn|
|Image|image_path|
|ParentImage|parent_image_path|
|ProcessId|pid|
|ParentProcessId|ppid|
|Company|signer|
|User|user|
|IntegrityLevel|integrity_level|
|ParentCommandLine|parent_command_line|
|CurrentDirectory|current_working_directory|
|Hashes|md5_hash|Extract MD5|
|Hashes|sha1_hash|Extract SHA1|
|Hashes|sha256_hash|Extract SHA256|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Image|exe|Extract basename|
|Computer|hostname|Extract computer name|
|ParentImage|parent_exe|Extract basename|


### Event ID 2: A process changed a file creation time
#### CAR `file timestomp`
|Sysmon|CAR|
|---|---|
|CreationUtcTime|creation_time|
|TargetFilename|file_path|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|
|PreviousCreationUtcTime|previous_creation_time|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|TargetFilename|file_name|Extract basename|


### Event ID 3: Network connection
#### CAR `flow start`
|Sysmon|CAR|
|---|---|
|DestinationIp|dest_ip|
|DestinationPort|dest_port|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|
|Protocol|protocol|
|SourceIp|src_ip|
|SourcePort|src_port|
|UtcTime|start_time|
|User|user|
|SourceHostname|src_fqdn|
|DestinationHostname|dest_fqdn|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Image|exe|Extract basename|
|Computer|hostname|Extract computer name|
|SourceHostname|src_hostname|Extract host name|
|DestinationHostname|dest_hostname|Extract host name|


### Event ID 5: Process terminated
#### CAR `process terminate`
|Sysmon|CAR|
|---|---|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Image|exe|Extract basename|
|Computer|hostname|Extract computer name|


### Event ID 6: Driver loaded
#### CAR `driver load`
|Sysmon|CAR|
|---|---|
|Computer|fqdn|
|ImageLoaded|image_path|
|Signature|signer|
|Hashes|md5_hash|Extract MD5|
|Hashes|sha1_hash|Extract SHA1|
|Hashes|sha256_hash|Extract SHA256|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|


### Event ID 7: Image loaded
#### CAR `module load`
|Sysmon|CAR|
|---|---|
|Computer|fqdn|
|Image|image_path|
|ImageLoaded|module_path|
|ProcessId|pid|
|Signature|signer|
|Hashes|md5_hash|Extract MD5|
|Hashes|sha1_hash|Extract SHA1|
|Hashes|sha256_hash|Extract SHA256|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|ImageLoaded|module_name|Extract basename|


### Event ID 8: CreateRemoteThread
#### CAR `thread remote_create`
|Sysmon|CAR|
|---|---|
|SourceProcessId|src_pid|
|StartAddress|start_address|
|TargetProcessId|tgt_pid|
|NewThreadId|tgt_tid|
|StartFunction|start_function|
|StartModule|start_module|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|StartModule|start_module_name|Extract basename|


### Event ID 11: FileCreate
#### CAR `file create`
|Sysmon|CAR|
|---|---|
|CreationUtcTime|creation_time|
|TargetFilename|file_path|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|TargetFilename|file_name|Extract basename|


### Event ID 12: RegistryEvent (Object create and delete)
#### CAR `registry add` `registry remove`
|Sysmon|CAR|
|---|---|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|
|TargetObject|key|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|TargetObject|value|Extract value|
|TargetObject|hive|Extract hive|


### Event ID 13: RegistryEvent (Value Set)
#### CAR `registry edit`
|Sysmon|CAR|
|---|---|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|
|TargetObject|key|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|TargetObject|value|Extract value|
|TargetObject|hive|Extract hive|


### Event ID 23: FileDelete (A file delete was detected)
#### CAR `file delete`
|Sysmon|CAR|
|---|---|
|TargetFilename|file_path|
|Computer|fqdn|
|Image|image_path|
|ProcessId|pid|
|User|user|
|Hashes|md5_hash|Extract MD5|
|Hashes|sha1_hash|Extract SHA1|
|Hashes|sha256_hash|Extract SHA256|

Fields that require a transformation
|Sysmon|CAR|Transformation|
|---|---|---|
|Computer|hostname|Extract computer name|
|TargetFilename|file_name|Extract basename|
