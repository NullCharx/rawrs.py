import dns.resolver

import dns.resolver
import dns.query

def is_dns_server(address):
    try:
        # Attempt to resolve a known domain using the provided address
        dns.query.udp(dns.message.make_query('google.com', dns.rdatatype.A), address)
        return True
    except Exception:
        return False



def enumerate_subdomains(domain, subdomain_list):
    found_subdomains = []
    for subdomain in subdomain_list:
        full_domain = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except Exception:
            continue
    return found_subdomains

# Example usage
domain = 'example.com'
subdomain_list = ['www', 'mail', 'ftp', 'test']
print(enumerate_subdomains(domain, subdomain_list))


def query_dns_records(domain, record_type):
    try:
        records = dns.resolver.resolve(domain, record_type)
        return [str(record) for record in records]
    except Exception as e:
        return str(e)

# Example usage
domain = 'example.com'
print(query_dns_records(domain, 'A'))  # Get A records
print(query_dns_records(domain, 'MX'))  # Get MX records


def reverse_dns_lookup(ip_address):
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        domain_name = dns.resolver.resolve(reverse_name, 'PTR')
        return [str(name) for name in domain_name]
    except Exception as e:
        return str(e)

# Example usage
ip_address = '8.8.8.8'
print(reverse_dns_lookup(ip_address))


def get_soa_record(domain):
    try:
        soa_record = dns.resolver.resolve(domain, 'SOA')
        return [str(record) for record in soa_record]
    except Exception as e:
        return str(e)

# Example usage
domain = 'example.com'
print(get_soa_record(domain))


def enumerate_subdomains(domain, subdomain_list):
    found_subdomains = []
    for subdomain in subdomain_list:
        full_domain = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except Exception:
            continue
    return found_subdomains

# Example usage
domain = 'example.com'
subdomain_list = ['www', 'mail', 'ftp', 'test']
print(enumerate_subdomains(domain, subdomain_list))
