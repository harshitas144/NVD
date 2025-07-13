# nmap_parser.py
import xml.etree.ElementTree as ET

def parse_nmap_xml(file):
    """
    Parses Nmap XML scan output and extracts service info.

    Args:
        file: An XML file-like object or file path.

    Returns:
        List of dicts with keys: ip, port, protocol, service, product, version.
    """
    if isinstance(file, str):  # If a path is passed
        tree = ET.parse(file)
    else:  # If a file-like object is passed (e.g., from Flask upload or Colab)
        tree = ET.parse(file)

    root = tree.getroot()
    results = []

    for host in root.findall('host'):
        ip_element = host.find('address')
        ip = ip_element.get('addr') if ip_element is not None else "unknown"

        ports = host.find('ports')
        if not ports:
            continue

        for port in ports.findall('port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')

            state = port.find('state')
            if state is not None and state.get('state') != 'open':
                continue  # Skip closed ports

            service = port.find('service')
            if service is None:
                continue

            name = service.get('name', 'unknown')
            product = service.get('product', 'unknown')
            version = service.get('version', 'unknown')

            results.append({
                "ip": ip,
                "port": port_id,
                "protocol": protocol,
                "service": name,
                "product": product,
                "version": version
            })

    return results

