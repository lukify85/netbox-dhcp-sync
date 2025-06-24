# NetBox DHCP Sync

A Python script that synchronizes DHCP server data with NetBox IPAM. This tool connects to Windows DHCP servers via PowerShell remoting, retrieves scope and lease information, and updates NetBox with IP ranges and IP addresses.

## Features

- **DHCP Scope Synchronization**: Creates and updates IP ranges in NetBox based on DHCP scopes
- **DHCP Lease Synchronization**: Creates and updates IP addresses with hostnames and MAC addresses
- **OUI Lookup**: Performs MAC address vendor identification using OUI database
- **Multi-Server Support**: Supports multiple DHCP servers across different domains
- **Duplicate Handling**: Intelligently handles duplicate IP addresses with different subnet masks
- **Comprehensive Logging**: Timestamped logs with detailed operation tracking
- **Secure Configuration**: Template-based configuration with credential separation

## Prerequisites

- Python 3.8+
- NetBox instance with API access
- Windows DHCP servers with WinRM enabled
- MAC OUI lookup database (JSON format)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/netbox-dhcp-sync.git
cd netbox-dhcp-sync
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Copy the configuration template:
```bash
cp config.py.template config.py
```

4. Edit `config.py` with your specific settings:
   - NetBox URL and API token
   - DHCP server list and credentials
   - Certificate paths
   - OUI database path

## Configuration

### NetBox Setup

Ensure your NetBox instance has:
- A role named "DHCP_RANGE_PRESENT" for IP ranges
- Custom fields for IP addresses:
  - `macAddress` (text field)
  - `macOUI` (text field)

### DHCP Server Setup

Enable WinRM on your DHCP servers:
```powershell
Enable-PSRemoting -Force
winrm quickconfig -quiet
```

### Configuration File

The `config.py` file contains:
- **NETBOX_URL**: Your NetBox instance URL
- **NETBOX_TOKEN**: NetBox API token
- **TLS_ROOT_CHAIN**: Path to SSL certificate for NetBox
- **OUI_JSON_PATH**: Path to MAC OUI lookup JSON file
- **DHCP_SERVERS**: Dictionary mapping DHCP server FQDNs to domains
- **DHCP_CREDENTIALS**: Domain credentials for DHCP server access

## Usage

Run the synchronization script:
```bash
python dhcp_sync.py
```

The script will:
1. Connect to each configured DHCP server
2. Retrieve DHCP scopes and leases
3. Create/update IP ranges in NetBox for active scopes
4. Create/update IP addresses with hostnames and MAC information
5. Perform OUI lookups for vendor identification
6. Generate detailed logs in the `./logs/` directory

## Logging

Logs are stored in `./logs/` with timestamps:
- Format: `dhcp_sync_{log_level}_{timestamp}.log`
- Example: `dhcp_sync_info_20250624_153045.log`

## Security Considerations

- **Never commit `config.py`** - It contains sensitive credentials
- Use dedicated service accounts with minimal required permissions
- Consider using environment variables or secrets management for production
- Ensure WinRM is properly secured on DHCP servers

## Troubleshooting

### Common Issues

1. **WinRM Connection Refused**: Ensure WinRM is enabled on DHCP servers
2. **Authentication Failures**: Verify credentials and domain settings
3. **SSL Certificate Errors**: Check TLS_ROOT_CHAIN path and certificate validity
4. **NetBox API Errors**: Verify API token permissions and NetBox connectivity

### Debug Mode

Set `LOG_LEVEL = 'DEBUG'` in config.py for detailed troubleshooting information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions, please open a GitHub issue with:
- Error messages and logs
- Configuration details (sanitized)
- Environment information