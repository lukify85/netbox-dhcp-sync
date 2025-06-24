#!/root/netbox-dhcp-sync/venv/bin/python

import os
import json
import ipaddress
import logging
from datetime import datetime
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import pynetbox

# Import variables from config.py
import config

# --- Configuration & Setup ---
LOG_FILE = config.LOG_FILE
LOG_LEVEL = config.LOG_LEVEL

# Create logs directory if it doesn't exist
logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(logs_dir, exist_ok=True)

# Create unique log file name with timestamp
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
log_filename = f"dhcp_sync_{LOG_LEVEL.lower()}_{timestamp}.log"
log_filepath = os.path.join(logs_dir, log_filename)

logging.basicConfig(level=getattr(logging, LOG_LEVEL), # Convert string level to logging constant
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(log_filepath),
                        logging.StreamHandler()
                    ])

# NetBox API
try:
    netbox_url = config.NETBOX_URL
    netbox_token = config.NETBOX_TOKEN
    nb = pynetbox.api(netbox_url, token=netbox_token)
    
    # Always use the custom TLS certificate
    if os.path.exists(config.TLS_ROOT_CHAIN):
        nb.http_session.verify = config.TLS_ROOT_CHAIN
        logging.info(f"Using custom TLS certificate: {config.TLS_ROOT_CHAIN}")
    else:
        logging.error(f"TLS certificate file not found: {config.TLS_ROOT_CHAIN}")
        exit(1)
    
    logging.info(f"Connected to NetBox at {netbox_url}")
except Exception as e:
    logging.error(f"Failed to connect to NetBox: {e}")
    exit(1)

# List of DHCP servers to process
DHCP_SERVERS = config.DHCP_SERVERS

# --- Functions ---

# Cache for NetBox role lookups
_role_cache = {}

# Track processed IP addresses during script runtime to avoid duplicates
_processed_ips = set()

# Cache for OUI lookups
_oui_cache = None

def load_oui_data():
    """
    Load OUI data from JSON file with caching to avoid repeated file reads.
    """
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    
    try:
        if os.path.exists(config.OUI_JSON_PATH):
            with open(config.OUI_JSON_PATH, 'r', encoding='utf-8') as f:
                _oui_cache = json.load(f)
                logging.info(f"Loaded {len(_oui_cache)} OUI entries from {config.OUI_JSON_PATH}")
                return _oui_cache
        else:
            logging.warning(f"OUI JSON file not found: {config.OUI_JSON_PATH}")
            _oui_cache = {}
            return _oui_cache
    except Exception as e:
        logging.error(f"Error loading OUI data: {e}")
        _oui_cache = {}
        return _oui_cache

def lookup_oui(mac_address):
    """
    Lookup OUI (vendor) information for a MAC address.
    Returns the vendor name or None if not found.
    """
    if not mac_address or len(mac_address) < 8:
        return None
    
    oui_data = load_oui_data()
    if not oui_data:
        return None
    
    # Extract first 3 octets (6 characters) and format as XX-XX-XX
    mac_clean = mac_address.replace('-', '').replace(':', '').upper()
    if len(mac_clean) >= 6:
        oui = f"{mac_clean[0:2]}-{mac_clean[2:4]}-{mac_clean[4:6]}"
        vendor = oui_data.get(oui)
        if vendor:
            logging.debug(f"Found OUI for {mac_address}: {oui} -> {vendor}")
        return vendor
    
    return None

def get_netbox_role_id(role_name):
    """
    Get the NetBox role ID by name, with caching to avoid repeated lookups.
    """
    if role_name in _role_cache:
        return _role_cache[role_name]
    
    try:
        # Look up the role by name
        role = nb.ipam.roles.get(name=role_name)
        if role:
            _role_cache[role_name] = role.id
            logging.info(f"Found role '{role_name}' with ID: {role.id}")
            return role.id
        else:
            logging.error(f"Role '{role_name}' not found in NetBox")
            return None
    except Exception as e:
        logging.error(f"Error looking up role '{role_name}': {e}")
        return None

def get_dhcp_credentials(domain_name):
    """
    Retrieves credentials for a given domain from the DHCP_CREDENTIALS dictionary.
    """
    credentials = config.DHCP_CREDENTIALS.get(domain_name)
    if credentials:
        return credentials.get('username'), credentials.get('password')
    else:
        logging.error(f"No DHCP credentials found for domain '{domain_name}'.")
        return None, None

def get_dhcp_data(dhcp_server_fqdn, username, password):
    """
    Connects to a remote DHCP server and scrapes scope and lease data.
    """
    logging.info(f"Attempting to connect to DHCP server: {dhcp_server_fqdn}")
    wsman = None
    try:
        wsman = WSMan(dhcp_server_fqdn,
                      username=username,
                      password=password,
                      auth_method='ntlm',
                      port=5985,
                      ssl=False) 

        with RunspacePool(wsman) as pool:
            # Get Scopes
            ps = PowerShell(pool)
            ps.add_script("Get-DhcpServerv4Scope | ConvertTo-Json -Depth 5")
            logging.info(f"Executing Get-DhcpServerv4Scope on {dhcp_server_fqdn}...")
            output_scopes = ps.invoke()
            if ps.streams.error:
                for error in ps.streams.error:
                    error_msg = getattr(error, 'exception_message', str(error))
                    logging.error(f"Error getting scopes from {dhcp_server_fqdn}: {error_msg}")
                return None, None
            scopes_json = "\n".join(output_scopes)
            scopes = json.loads(scopes_json)
            logging.info(f"Retrieved {len(scopes)} scopes from {dhcp_server_fqdn}.")

            all_leases = []
            for scope in scopes:
                # Handle the case where ScopeId might be a complex object
                if isinstance(scope['ScopeId'], dict):
                    scope_id = scope['ScopeId'].get('IPAddressToString', str(scope['ScopeId']))
                else:
                    scope_id = str(scope['ScopeId'])
                
                ps_lease = PowerShell(pool)
                script = f"Get-DhcpServerv4Lease -ScopeId '{scope_id}' -AllLeases | ConvertTo-Json -Depth 5"
                ps_lease.add_script(script)
                logging.info(f"Executing Get-DhcpServerv4Lease for scope {scope_id} on {dhcp_server_fqdn}...")
                output_leases = ps_lease.invoke()
                if ps_lease.streams.error:
                    for error in ps_lease.streams.error:
                        error_msg = getattr(error, 'exception_message', str(error))
                        logging.warning(f"Error getting leases for scope {scope_id} on {dhcp_server_fqdn}: {error_msg}")
                    continue
                leases_json = "\n".join(output_leases)
                if leases_json.strip():  # Check if we have actual data
                    leases = json.loads(leases_json)
                    # Handle case where single lease is returned as dict instead of list
                    if isinstance(leases, dict):
                        leases = [leases]
                    all_leases.extend(leases)
                    logging.info(f"Retrieved {len(leases)} leases for scope {scope_id}.")
                else:
                    logging.info(f"No leases found for scope {scope_id}.")

            return scopes, all_leases

    except Exception as e:
        logging.error(f"Failed to get DHCP data from {dhcp_server_fqdn}: {e}")
        return None, None
    finally:
        if wsman:
            try:
                wsman.close()
                logging.info(f"Closed WSMan session to {dhcp_server_fqdn}.")
            except Exception as e:
                logging.warning(f"Error closing WSMan session to {dhcp_server_fqdn}: {e}")


def sync_to_netbox(dhcp_scopes, dhcp_leases, dhcp_server_fqdn):
    """
    Synchronizes DHCP data to NetBox.
    """
    logging.info(f"Starting NetBox synchronization for {dhcp_server_fqdn}...")

    # Create/Update IP Ranges (DHCP Scopes)
    for scope in dhcp_scopes:
        # Handle complex ScopeId object
        if isinstance(scope['ScopeId'], dict):
            scope_id = scope['ScopeId'].get('IPAddressToString')
        else:
            scope_id = str(scope['ScopeId'])
            
        scope_name = scope.get('Name', f"DHCP Scope {scope_id}")
        scope_state = scope.get('State', 'Unknown')
        
        # Skip inactive scopes
        if scope_state == 'Inactive':
            logging.info(f"Skipping inactive DHCP scope {scope_name} ({scope_id}).")
            continue
        
        # Handle complex IP address objects
        if isinstance(scope['StartRange'], dict):
            start_ip = scope['StartRange'].get('IPAddressToString')
        else:
            start_ip = str(scope['StartRange'])
            
        if isinstance(scope['EndRange'], dict):
            end_ip = scope['EndRange'].get('IPAddressToString')
        else:
            end_ip = str(scope['EndRange'])
            
        # Handle complex subnet mask objects and calculate prefix length
        if isinstance(scope['SubnetMask'], dict):
            subnet_mask = scope['SubnetMask'].get('IPAddressToString')
        else:
            subnet_mask = str(scope['SubnetMask'])
            
        try:
            prefix_len = ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen
            start_ip_with_mask = f"{start_ip}/{prefix_len}"
            end_ip_with_mask = f"{end_ip}/{prefix_len}"
        except Exception as e:
            logging.error(f"Error calculating prefix length for scope {scope_id}: {e}")
            continue

        try:
            # Get the role ID for DHCP_RANGE_PRESENT
            role_id = get_netbox_role_id("DHCP_RANGE_PRESENT")
            if not role_id:
                logging.error(f"Cannot create IP Range for scope {scope_id} - role 'DHCP_RANGE_PRESENT' not found")
                continue
                
            # Check if IP Range already exists
            netbox_range = nb.ipam.ip_ranges.get(
                start_address=start_ip,
                end_address=end_ip
            )
            
            range_data = {
                "start_address": start_ip_with_mask,
                "end_address": end_ip_with_mask,
                "status": "active",
                "role": role_id,
                "description": scope_name,
                "comments": f"DHCP Scope from {dhcp_server_fqdn}"
            }

            if netbox_range:
                logging.info(f"Updating IP Range {scope_name} ({start_ip_with_mask}-{end_ip_with_mask}).")
                netbox_range.update(range_data)
            else:
                logging.info(f"Creating IP Range {scope_name} ({start_ip_with_mask}-{end_ip_with_mask}).")
                nb.ipam.ip_ranges.create(**range_data)

        except Exception as e:
            logging.error(f"Error syncing scope {scope_id} to NetBox: {e}")

    # Create/Update IP Addresses
    for lease in dhcp_leases:
        # Handle complex IP address objects
        if isinstance(lease['IPAddress'], dict):
            ip_address = lease['IPAddress'].get('IPAddressToString')
        else:
            ip_address = str(lease['IPAddress'])
            
        client_id = lease.get('ClientId')
        hostname = lease.get('HostName')
        lease_status = lease.get('AddressState')
        
        # Find the scope this lease belongs to for subnet mask
        lease_scope = None
        for scope in dhcp_scopes:
            if isinstance(scope['ScopeId'], dict):
                scope_network = scope['ScopeId'].get('IPAddressToString')
            else:
                scope_network = str(scope['ScopeId'])
                
            if isinstance(scope['SubnetMask'], dict):
                subnet_mask = scope['SubnetMask'].get('IPAddressToString')
            else:
                subnet_mask = str(scope['SubnetMask'])
                
            try:
                prefix_len = ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen
                network = ipaddress.ip_network(f"{scope_network}/{prefix_len}", strict=False)
                if ipaddress.ip_address(ip_address) in network:
                    lease_scope = scope
                    break
            except Exception:
                continue
        
        if not lease_scope:
            logging.warning(f"Could not find scope for IP {ip_address}, using /32")
            full_ip_address = f"{ip_address}/32"
        else:
            if isinstance(lease_scope['SubnetMask'], dict):
                subnet_mask = lease_scope['SubnetMask'].get('IPAddressToString')
            else:
                subnet_mask = str(lease_scope['SubnetMask'])
            prefix_len = ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}').prefixlen
            full_ip_address = f"{ip_address}/{prefix_len}"

        # Clean up MAC address format (remove hyphens, convert to uppercase)
        cleaned_mac = None
        vendor_name = None
        if client_id and len(client_id) >= 12:
            mac_clean = client_id.replace('-', '').replace(':', '').upper()
            if len(mac_clean) == 12:
                cleaned_mac = mac_clean
                # Perform OUI lookup for vendor information
                vendor_name = lookup_oui(client_id)

        # Clean up hostname (replace spaces and invalid DNS characters with underscores)
        clean_hostname = None
        if hostname:
            import re
            # Replace any character that's not alphanumeric, asterisk, hyphen, period, or underscore with underscore
            clean_hostname = re.sub(r'[^a-zA-Z0-9*\-._]', '_', hostname)

        # Skip processing if this IP has already been handled
        if full_ip_address in _processed_ips:
            logging.info(f"IP address {full_ip_address} has already been processed. Skipping.")
            continue
        _processed_ips.add(full_ip_address)

        try:
            netbox_ip = nb.ipam.ip_addresses.get(address=full_ip_address)
            
            ip_data = {
                "address": full_ip_address,
                "status": "dhcp"
            }
            
            # Only add dns_name if we have a valid hostname
            if clean_hostname:
                ip_data["dns_name"] = clean_hostname
            
            # Add custom fields if available
            custom_fields = {}
            if cleaned_mac:
                custom_fields["macAddress"] = cleaned_mac
            if vendor_name:
                custom_fields["macOUI"] = vendor_name
            
            if custom_fields:
                ip_data["custom_fields"] = custom_fields
            
            if not netbox_ip:
                vendor_info = f" (Vendor: {vendor_name})" if vendor_name else ""
                logging.info(f"Creating IP Address {full_ip_address} with hostname {clean_hostname}{vendor_info}.")
                try:
                    netbox_ip = nb.ipam.ip_addresses.create(**ip_data)
                    if not netbox_ip:
                        logging.error(f"Failed to create IP address {full_ip_address}.")
                        continue
                except Exception as create_error:
                    error_str = str(create_error)
                    # Check if it's a duplicate IP error and extract the existing IP address
                    if "Duplicate IP address found in global table:" in error_str:
                        import re
                        match = re.search(r'Duplicate IP address found in global table: ([0-9\.]+/\d+)', error_str)
                        if match:
                            existing_ip_address = match.group(1)
                            logging.info(f"Found duplicate IP {existing_ip_address}, updating to correct subnet mask {full_ip_address}")
                            # Get the existing IP by its exact address
                            netbox_ip = nb.ipam.ip_addresses.get(address=existing_ip_address)
                            if netbox_ip:
                                # Update with correct subnet mask and DHCP data
                                update_data = {
                                    'address': full_ip_address,
                                    'status': 'dhcp'
                                }
                                # Only add dns_name if we have a valid hostname
                                if clean_hostname:
                                    update_data['dns_name'] = clean_hostname
                                if custom_fields:
                                    update_data['custom_fields'] = custom_fields
                                
                                vendor_info = f" (Vendor: {vendor_name})" if vendor_name else ""
                                logging.info(f"Updating duplicate IP {existing_ip_address} to {full_ip_address}{vendor_info}.")
                                netbox_ip.update(update_data)
                                continue
                        logging.error(f"Could not extract existing IP address from error: {error_str}")
                        continue
                    else:
                        # Re-raise the error if it's not a duplicate IP issue
                        raise create_error
            else:
                # Update existing IP
                update_data = {}
                
                # Always update the address to ensure correct subnet mask
                if netbox_ip.address != full_ip_address:
                    update_data['address'] = full_ip_address
                    logging.info(f"Updating subnet mask for {netbox_ip.address} to {full_ip_address}")
                
                # Only update dns_name if we have a valid hostname
                if clean_hostname and netbox_ip.dns_name != clean_hostname:
                    update_data['dns_name'] = clean_hostname
                elif not clean_hostname and netbox_ip.dns_name:
                    # Clear the dns_name if we don't have a hostname but NetBox has one
                    update_data['dns_name'] = ""
                    
                update_data['status'] = "dhcp"
                
                # Update custom fields
                current_custom_fields = {}
                if cleaned_mac:
                    current_mac = getattr(netbox_ip.custom_fields, 'macAddress', None) if hasattr(netbox_ip, 'custom_fields') else None
                    if current_mac != cleaned_mac:
                        current_custom_fields["macAddress"] = cleaned_mac
                
                if vendor_name:
                    current_vendor = getattr(netbox_ip.custom_fields, 'macOUI', None) if hasattr(netbox_ip, 'custom_fields') else None
                    if current_vendor != vendor_name:
                        current_custom_fields["macOUI"] = vendor_name
                
                if current_custom_fields:
                    update_data['custom_fields'] = current_custom_fields
                        
                if update_data:
                    vendor_info = f" (Vendor: {vendor_name})" if vendor_name else ""
                    logging.info(f"Updating IP address {netbox_ip.address}{vendor_info} with {update_data}.")
                    netbox_ip.update(update_data)
                else:
                    logging.info(f"IP address {full_ip_address} is up to date.")

        except Exception as e:
            logging.error(f"Error syncing lease {ip_address} to NetBox: {e}")

    logging.info(f"Finished NetBox synchronization for {dhcp_server_fqdn}.")

# --- Main Execution Flow ---
def main():
    for dhcp_server, domain_name in DHCP_SERVERS.items():
        logging.info(f"Processing DHCP server: {dhcp_server} (Domain: {domain_name})")
        username, password = get_dhcp_credentials(domain_name)

        if not username or not password:
            logging.error(f"Skipping {dhcp_server} due to missing credentials.")
            continue

        scopes, leases = get_dhcp_data(dhcp_server, username, password)

        if scopes is not None and leases is not None:
            sync_to_netbox(scopes, leases, dhcp_server)
        else:
            logging.error(f"Failed to retrieve DHCP data from {dhcp_server}.")

    logging.info("DHCP to NetBox synchronization complete.")

if __name__ == "__main__":
    main()
