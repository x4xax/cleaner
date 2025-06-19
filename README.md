# Xbox Live Cleaner

A lightweight utility for cleaning up Xbox Live-related files, registry entries, and credentials to resolve issues with Xbox applications on Windows.

## Features

- Terminates Xbox-related processes to ensure clean access to files
- Removes problematic Xbox credentials from Windows Credential Manager
- Cleans Xbox-related registry entries that can cause connection issues
- Blocks known telemetry servers via hosts file modification
- Flushes DNS cache to resolve connection problems
- Cleans temporary files from Xbox app packages
- Windows 11 support with automatic detection
- For Windows 11: Automatically resets Xbox gaming-related Windows apps

## Usage

1. Run the application as Administrator (required for system file access)
2. The utility will automatically:
   - Clean Xbox credentials
   - Block problematic hosts
   - Clean registry entries
   - Flush DNS cache
   - Delete temporary package files
   - Reset Xbox apps (Windows 11 only)
3. Wait for the "Cleaning complete" message
4. Restart your computer

## When to Use

This tool can help resolve various Xbox-related issues on Windows:
- Xbox app sign-in problems
- "Gaming services need repair" errors
- Xbox Game Pass app failing to launch games
- Authentication loops in the Xbox app
- Connection issues with Xbox Live

## System Requirements

- Windows 10 or Windows 11
- Administrator privileges
- Visual C++ Redistributable 2019 or newer

## Building from Source

### Prerequisites
- Visual Studio 2019/2022 with C++20 support
- Windows SDK 10.0 or later

### Build Steps
1. Open the solution in Visual Studio
2. Build in Release configuration
3. Run the resulting executable as Administrator

## License

This project is open-source software.

## Warning

This tool modifies system files and registry entries. Use at your own risk.
Always ensure you have system backups before running system cleaning utilities.
