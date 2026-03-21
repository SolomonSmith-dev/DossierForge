import subprocess
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

def run_nmap_scan(target, dossier_path, scan_type='basic'):
    """
    Run nmap scan on a target and save results to dossier.
    
    Args:
        target (str): IP address or hostname to scan
        dossier_path (str): Path to dossier directory
        scan_type (str): Type of scan ('basic', 'full', 'vuln')
    
    Returns:
        dict: Parsed nmap data
    """
    try:
        # Define scan options based on type
        if scan_type == 'basic':
            args = ['nmap', '-sS', '-sV', '-O', '-oX', '-', target]
        elif scan_type == 'full':
            args = ['nmap', '-sS', '-sV', '-O', '-p-', '-oX', '-', target]
        elif scan_type == 'vuln':
            args = ['nmap', '--script=vuln', '-sV', '-oX', '-', target]
        else:
            args = ['nmap', '-sS', '-sV', '-O', '-oX', '-', target]
        
        # Run nmap
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return {'error': f'Nmap scan failed: {result.stderr}'}
        
        xml_output = result.stdout
        
        # Save raw XML output
        xml_file = os.path.join(dossier_path, f'nmap_{scan_type}.xml')
        with open(xml_file, 'w') as f:
            f.write(xml_output)
        
        # Parse XML output
        parsed_data = parse_nmap_xml(xml_output, target, scan_type)
        
        # Save parsed data
        parsed_file = os.path.join(dossier_path, f'nmap_{scan_type}_parsed.json')
        with open(parsed_file, 'w') as f:
            json.dump(parsed_data, f, indent=2)
        
        return parsed_data
        
    except subprocess.TimeoutExpired:
        return {'error': 'Nmap scan timed out'}
    except Exception as e:
        return {'error': f'Nmap scan failed: {str(e)}'}

def parse_nmap_xml(xml_content, target, scan_type):
    """
    Parse nmap XML output to extract key information.
    
    Args:
        xml_content (str): Raw nmap XML output
        target (str): Original target scanned
        scan_type (str): Type of scan performed
    
    Returns:
        dict: Parsed nmap data
    """
    try:
        root = ET.fromstring(xml_content)
        parsed = {
            'target': target,
            'scan_type': scan_type,
            'scan_time': datetime.now().isoformat(),
            'hosts': []
        }
        
        for host in root.findall('.//host'):
            host_data = parse_host_element(host)
            if host_data:
                parsed['hosts'].append(host_data)
        
        return parsed
        
    except ET.ParseError as e:
        return {'error': f'Failed to parse nmap XML: {str(e)}'}

def parse_host_element(host):
    """
    Parse a single host element from nmap XML.
    
    Args:
        host: XML element representing a host
    
    Returns:
        dict: Parsed host data
    """
    host_data = {
        'addresses': [],
        'ports': [],
        'os_info': {},
        'status': 'unknown'
    }
    
    # Parse addresses
    for addr in host.findall('.//address'):
        addr_type = addr.get('addrtype', '')
        addr_value = addr.get('addr', '')
        if addr_type and addr_value:
            host_data['addresses'].append({
                'type': addr_type,
                'address': addr_value
            })
    
    # Parse status
    status_elem = host.find('.//status')
    if status_elem is not None:
        host_data['status'] = status_elem.get('state', 'unknown')
    
    # Parse ports
    for port in host.findall('.//port'):
        port_data = parse_port_element(port)
        if port_data:
            host_data['ports'].append(port_data)
    
    # Parse OS info
    os_elem = host.find('.//os')
    if os_elem is not None:
        for osmatch in os_elem.findall('.//osmatch'):
            host_data['os_info'] = {
                'name': osmatch.get('name', ''),
                'accuracy': osmatch.get('accuracy', ''),
                'line': osmatch.get('line', '')
            }
            break  # Take the first (most accurate) match
    
    return host_data

def parse_port_element(port):
    """
    Parse a single port element from nmap XML.
    
    Args:
        port: XML element representing a port
    
    Returns:
        dict: Parsed port data
    """
    port_id = port.get('portid', '')
    protocol = port.get('protocol', '')
    state = port.find('.//state')
    service = port.find('.//service')
    
    if not port_id or not protocol:
        return None
    
    port_data = {
        'port': int(port_id),
        'protocol': protocol,
        'state': state.get('state', 'unknown') if state is not None else 'unknown',
        'service': {}
    }
    
    if service is not None:
        port_data['service'] = {
            'name': service.get('name', ''),
            'product': service.get('product', ''),
            'version': service.get('version', ''),
            'extrainfo': service.get('extrainfo', '')
        }
    
    return port_data

def get_nmap_summary(dossier_path):
    """
    Get a summary of nmap data for display in the UI.
    
    Args:
        dossier_path (str): Path to dossier directory
    
    Returns:
        dict: Summary of nmap data
    """
    summary = {
        'scans': [],
        'total_hosts': 0,
        'total_ports': 0,
        'open_ports': 0
    }
    
    # Look for parsed nmap files
    for filename in os.listdir(dossier_path):
        if filename.startswith('nmap_') and filename.endswith('_parsed.json'):
            try:
                with open(os.path.join(dossier_path, filename), 'r') as f:
                    data = json.load(f)
                
                scan_type = data.get('scan_type', 'unknown')
                hosts = data.get('hosts', [])
                
                scan_summary = {
                    'type': scan_type,
                    'target': data.get('target'),
                    'scan_time': data.get('scan_time'),
                    'hosts': len(hosts),
                    'open_ports': 0
                }
                
                # Count open ports
                for host in hosts:
                    for port in host.get('ports', []):
                        if port.get('state') == 'open':
                            scan_summary['open_ports'] += 1
                
                summary['scans'].append(scan_summary)
                summary['total_hosts'] += len(hosts)
                summary['open_ports'] += scan_summary['open_ports']
                
            except:
                continue
    
    return summary

def get_open_ports(dossier_path):
    """
    Get a list of all open ports from nmap scans.
    
    Args:
        dossier_path (str): Path to dossier directory
    
    Returns:
        list: List of open ports with service info
    """
    open_ports = []
    
    for filename in os.listdir(dossier_path):
        if filename.startswith('nmap_') and filename.endswith('_parsed.json'):
            try:
                with open(os.path.join(dossier_path, filename), 'r') as f:
                    data = json.load(f)
                
                for host in data.get('hosts', []):
                    for port in host.get('ports', []):
                        if port.get('state') == 'open':
                            open_ports.append({
                                'port': port.get('port'),
                                'protocol': port.get('protocol'),
                                'service': port.get('service', {}).get('name', ''),
                                'product': port.get('service', {}).get('product', ''),
                                'version': port.get('service', {}).get('version', ''),
                                'scan_type': data.get('scan_type')
                            })
                
            except:
                continue
    
    return open_ports 