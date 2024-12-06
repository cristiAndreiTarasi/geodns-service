from sys import stdin, stdout, stderr
import os
import random
import geoip2.database
import json
import datetime

# Configuration variables
DNS_mappings = '/var/lib/pdns/DNS_mappings.json'
default_ttl = '60'
auth_zone = 'example.com'

# PowerDNS server configuration
pdns_servers = ['pdns1', 'pdns2', 'pdns3']
pdns_ipaddresses = {
    'pdns1': '147.75.75.145',
    'pdns2': '85.236.43.108',
    'pdns3': '67.219.148.138'
}

# GeoIP database
geoip_cache = {}
geodb = geoip2.database.Reader('/etc/powerdns/GeoLite2-City.mmdb')

# Serial number for SOA records
soa_ver = datetime.datetime.today().strftime('%Y%m%d%H')

# Debugging flag
debug = False

def get_continent_code(ip):
    """
    Get the continent code for an IP address using GeoIP2. Results are cached.
    :param ip: The IP address to query.
    :return: Continent code (e.g., 'EU', 'AS').
    """
    if ip in geoip_cache:
        return geoip_cache[ip]

    try:
        continent_code = geodb.city(ip).continent.code
        geoip_cache[ip] = continent_code
        return continent_code
    except Exception as e:
        if debug:
            stderr.write(f"GeoIP lookup failed for IP {ip}: {e}\n")
        return 'NA'


def backend_init():
    """
    Initialize the backend by acknowledging PowerDNS.
    """
    stdin.readline()
    stdout.write("OK\tPDNS Custom Python Backend\n")
    stdout.flush()


def main():
    """
    Main function to handle incoming queries from PowerDNS.
    """
    backend_init()

    # Load backend configuration
    with open(DNS_mappings) as backend:
        nodes = json.load(backend)

    while True:
        data = stdin.readline().strip()

        if debug:
            stderr.write(f"Received: {data}\n")

        query_type, qname, qclass, qtype, id, ip = data.split('\t')
        role = qname.lower().replace(f'.{auth_zone}', '')

        # Resolve continent code using GeoIP
        continent_code = get_continent_code(ip)

        if debug:
            stderr.write(f"Query details: {qname}, {qclass}, {continent_code}, {ip}\n")

        # Determine host validity and retrieve IPs
        valid_host, pdns_host, ip_list, ip6_list = handle_query(role, nodes, continent_code)

        # Handle query response
        if query_type == 'Q':
            handle_query_response(
                valid_host, pdns_host, ip_list, ip6_list, qname, qclass, qtype, id, role, nodes
            )


def handle_query(role, nodes, continent_code):
    """
    Determine query validity and retrieve IPs based on role and continent.
    """
    if role in nodes:
        ip_list = nodes[role][continent_code]['ipv4']
        ip6_list = nodes[role][continent_code]['ipv6']
        valid_host = True
        pdns_host = False
    elif role in pdns_servers:
        ip_list = []
        ip6_list = []
        valid_host = True
        pdns_host = True
    else:
        ip_list = []
        ip6_list = []
        valid_host = False
        pdns_host = False
    return valid_host, pdns_host, ip_list, ip6_list


def handle_query_response(valid_host, pdns_host, ip_list, ip6_list, qname, qclass, qtype, id, role, nodes):
    """
    Generate and send appropriate DNS responses to PowerDNS.
    """
    dns_answer = ""
    if not valid_host:
        if (qtype in ['SOA', 'ANY']) and qname == auth_zone:
            dns_answer += generate_soa_record(qname, qclass)
        stdout.write(dns_answer + "END\n")
        stdout.flush()
        return

    # Valid host responses
    if (qtype in ['SOA', 'ANY']):
        dns_answer += generate_soa_record(qname, qclass)
    if (qtype in ['NS', 'ANY']):
        dns_answer += generate_ns_records(qname, qclass)
    if qtype in ['ANY', 'A', 'AAAA']:
        dns_answer += generate_a_aaaa_records(qtype, ip_list, ip6_list, qname, qclass, id, role, nodes, pdns_host)

    stdout.write(dns_answer + "END\n")
    stdout.flush()


def generate_soa_record(qname, qclass):
    """
    Generate SOA record.
    """
    return f"DATA\t{qname}\t{qclass}\tSOA\t86400\t-1\tpdns1.{auth_zone}\thostmaster.{auth_zone}\t{soa_ver} 1800 3600 604800 3600\n"


def generate_ns_records(qname, qclass):
    """
    Generate NS records.
    """
    records = ""
    for ns in pdns_servers:
        records += f"DATA\t{qname}\t{qclass}\tNS\t86400\t-1\t{ns}.{auth_zone}\n"
    return records


def generate_a_aaaa_records(qtype, ip_list, ip6_list, qname, qclass, id, role, nodes, pdns_host):
    """
    Generate A and AAAA records based on the query type.
    """
    records = ""
    if len(ip_list) > 0 and role not in ['buildlogs', 'cloud']:
        while len(ip_list) < 5:
            ip_list.append(random.choice(nodes[role]['NA']['ipv4']))
        ip_answer = random.choice(ip_list)
        records += f"DATA\t{qname}\t{qclass}\tA\t{default_ttl}\t{id}\t{ip_answer}\n"
    if qtype in ['ANY', 'AAAA'] and len(ip6_list) > 0:
        ip6_answer = random.choice(ip6_list)
        records += f"DATA\t{qname}\t{qclass}\tAAAA\t{default_ttl}\t{id}\t{ip6_answer}\n"
    return records


if __name__ == '__main__':
    main()
