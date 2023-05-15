import dns.resolver
import sys

domain = sys.argv[1]

# Create a function that given a domain, will return the DMARC policy for that domain.


def has_vulnerable_domain(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in mx_records:
            if 'google.com' in str(record.exchange) or 'outlook.com' in str(record.exchange):
                return True
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.exception.DNSException:
        return False


def get_mx(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in mx_records:
            if 'google.com' in str(record.exchange):
                return 'google mx'
            elif 'outlook.com' in str(record.exchange):
                return 'outlook mx'
        return 'Not vulnerable'
    except dns.resolver.NXDOMAIN:
        return 'Not vulnerable'
    except dns.resolver.NoAnswer:
        return 'Not vulnerable'
    except dns.exception.DNSException:
        return 'Not vulnerable'


def get_spf(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if '-all' in record.to_text():
                return 'Fail'
            elif '~all' in record.to_text():
                return 'SoftFail'
        return 'None'
    except dns.resolver.NXDOMAIN:
        return 'None'
    except dns.resolver.NoAnswer:
        return 'None'
    except dns.exception.DNSException:
        return 'None'


def get_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for record in txt_records:
            if 'p=quarantine' in record.to_text():
                return 'Quarantine'
            elif 'p=reject' in record.to_text():
                return 'Reject'
        return 'None'
    except dns.resolver.NXDOMAIN:
        return 'None'
    except dns.resolver.NoAnswer:
        return 'None'
    except dns.exception.DNSException:
        return 'None'


def get_vulnerable(domain):
    if not has_vulnerable_domain(domain):
        return False

    dmarc_result = get_dmarc(domain)
    spf_result = get_spf(domain)

    if dmarc_result == 'None':
        return True
    if dmarc_result == 'Quarantine' and spf_result == 'SoftFail':
        return True

    return False


def get_general_info(domain):
    return {
        'MX': get_mx(domain),
        'SPF': get_spf(domain),
        'DMARC': get_dmarc(domain),
        '!VULNERABLE!': get_vulnerable(domain)
    }


result = get_general_info(domain)
print(result)
