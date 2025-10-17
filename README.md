# Xbox Live Cleaner

A lightweight utility for cleaning up Xbox Live-related files, registry entries, and credentials to resolve issues with Xbox applications on Windows.

## Features

- Terminates Xbox-related processes to ensure clean access to files
- Removes problematic Xbox credentials from Windows Credential Manager
- Cleans Xbox-related registry entries that can cause connection issues
- Cleans temporary files from Xbox app packages

## Usage

1. Run the application as Administrator (required for system file access)
2. Wait for the "Cleaning complete" message

## Upcoming changes

- Deletion of some remaining secured credentials (SSO...)
- Session SID Spoofer

## System Requirements

- Windows 10+
- Administrator privileges

## VirusTotal scan
- The scan is available [here](https://www.virustotal.com/gui/file-analysis/ZTlkNDFlZGY1MDE3MWI4MDgwY2U5OGQ1MzExNjllMjA6MTc2MDcyODU3Mw==) .

## Building from Source

### Prerequisites
- Visual Studio 2019/2022 with C++20 support
- Windows SDK 10.0 or later

### Building Instructions
- Build with Visual Studio

## License

This project is open-source software.

## Warning

This tool modifies system files and registry entries. Use at your own risk.
Always ensure you have system backups before running system cleaning utilities.
