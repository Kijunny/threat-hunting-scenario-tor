# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Kijunny/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-11-29T18:08:19.0612161Z`
- **Event:** The user “kkang10” downloaded or acquired a file named tor-browser-windows-x86_64-portable-15.0.2.exe into the Downloads folder. This marks the beginning of Tor-related activity on the device.
- **Action:** File download detected.
- **File Path:** `C:\Users\kkang10\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-29T18:10:24.9290488Z`
- **Event:** User “kkang10” executed tor-browser-windows-x86_64-portable-15.0.2.exe from the Downloads folder, initiating installation of the Tor Browser. The execution appears silent, with no visible interaction.
- **Action:** Process creation detected.
- **Command:** `Tor-browser-windows-x86_64-portable-15.0.2.exe /S`
- **File Path:** `C:\Users\kkang10\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-11-29T18:10:54.767849Z`
- **Event:** User “kkang10” launched the Tor Browser. Additional Tor Browser–associated processes (including firefox.exe and tor.exe) were created immediately afterward, confirming a successful browser launch.
- **Action:** Process creation for Tor-related executables detected.
- **File Path:** `C:\Users\kkang10\Desktop\Tor\Browser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-29T18:11:17.580957Z`
- **Event:** A network connection to IP 37.218.242.26 on port 9001 was established using tor.exe, confirming the Tor Browser’s successful connection to the Tor network. Additional Tor-related traffic was observed on ports 443 and 9150, including loopback proxy communications.
- **Action:** Outbound network connection detected.
- **Connection Details:** `Remote IP: 37.218.242.26, Remote Port: 9001, Process: tor.exe`
- **File Path:** ` C:\Users\kkang10\Desktop\Tor\Browser\Tor\tor.exee`

### 5. File Creation – Tor Artifact on Desktop

- **Timestamps:** 2025-11-28T02:04:02.5725551Z
- **Event:** A file named tor-shopping-list.txt was created on the Desktop. Although this predates the installation events, it is a Tor-related artifact created by the same user and therefore relevant to the threat hunt.
- **Action:** File creation detected.
- **File Path:** `C:\Users\kkang10\Desktop\tor-shopping-list.txt`

---

## Summary

A review of file, process, and network telemetry on the key-threat-hunt device indicates that user “kkang10” carried out a complete sequence of Tor Browser activity on November 29, 2025. The user first downloaded the Tor Browser installer and then executed it directly from the Downloads folder. Shortly afterward, they successfully launched the Tor Browser, as confirmed by the creation of both firefox.exe and tor.exe processes. The device then established active connections to the Tor network, including outbound traffic to relay nodes on ports 9001 and 443, as well as communication through the local Tor proxy on port 9150. In addition to these events, several Tor-related files were extracted to the Desktop, and a Tor-associated text file had been created the previous day. Altogether, the collected evidence clearly indicates intentional installation and use of the Tor Browser on this device.

---

## Response Taken

TOR usage was confirmed on endpoint Key-threat-hunt by the user kkang10. The device was isolated and the user's direct manager was notified.

---
