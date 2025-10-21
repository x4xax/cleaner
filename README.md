# Xbox Live Cleaner

A lightweight utility for cleaning up Xbox Live-related files, registry entries, and credentials to resolve issues with Xbox applications on Windows.

## Features

- Terminates Xbox-related processes to ensure clean access to files
- Removes problematic Xbox credentials from Windows Credential Manager
- Changes various GUIDs
- Cleans Xbox-related registry entries that can cause connection issues
- Blocks known telemetry servers via hosts file modification
- Cleans temporary files from Xbox app packages
  
## Usage

1. Remove accounts from Windows settings
2. Run the application as Administrator (required for system file access)
3. Wait for the "Cleaning complete" message
4. Delete the remaning SSO_POP_DEVICE and virtulapp credentials
5. (Restart your computer)

## TODO
- Protected credentials removal
- MAC Spoofing
- Remove accounts from Windows settings

## License

This project is open-source software.

## Warning

This tool modifies system files and registry entries. Use at your own risk.
Always ensure you have system backups before running system cleaning utilities.
