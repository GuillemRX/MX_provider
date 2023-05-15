import subprocess
import sys

domain = sys.argv[1]

#Create a function that given a domain, will return the DMARC policy for that domain.
def has_vulnerable_domain(domain):
    p = subprocess.run('dig @8.8.8.8 '+domain+' MX +short', shell=True, capture_output=True)
    return "google.com" in str(p.stdout) or "outlook.com" in str(p.stdout)

def get_mx(domain):
    p = subprocess.run('dig @8.8.8.8 '+domain+' MX +short', shell=True, capture_output=True)
    if "google.com" in str(p.stdout):
        return "google mx"
    
    if "outlook.com" in str(p.stdout):
        return "outlook mx"

    return "Not vulnerable"
    

def get_spf(domain):
    p = subprocess.run('dig @8.8.8.8 '+domain+' txt +short', shell=True, capture_output=True)
    
    if "-all" in str(p.stdout):
        return "Fail"
    if "~all" in str(p.stdout):
        return "SoftFail"
    
    return "None"

def get_dmarc(domain):
    p = subprocess.run('dig @8.8.8.8 _dmarc.'+domain+' txt +short', shell=True, capture_output=True)

    if "p=quarantine" in str(p.stdout):
        return "Quarantine"

    if "p=reject" in str(p.stdout):
        return "Reject"
        
    return "None"


def get_vulnerable(domain):
    if not has_vulnerable_domain(domain):
        return False

    if "None" in get_dmarc(domain):
        return True
    if "Quarantine" in get_dmarc(domain) and "SoftFail" in get_spf(domain):
        return True

    return False


def get_general_info(domain):
    return {
        "MX" : get_mx(domain),
        "SPF" : get_spf(domain),
        "DMARC" : get_dmarc(domain),
        "!VULNERABLE!" : get_vulnerable(domain)
    }
    


result = get_general_info(domain)
print (result)