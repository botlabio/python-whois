from .net import get_reg_whois, get_whois_raw
from .parse import parse_raw_whois

def get_records(domain, debug=False):

    try:
        server = get_reg_whois(domain)
    except:
        server = None
        
    raw = get_whois_raw(domain, server=server)
    
    record = parse_raw_whois(raw)
    
    if debug == False:
        
        out = domain + ','
        
        try:
            out += record['creation_date'][0].strftime("%Y") + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['expiration_date'][0].strftime("%Y") + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['nameservers'][0] + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['nameservers'][1] + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try: 
            org = record['contacts']['registrant']['organization'] + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['contacts']['registrant']['name'] + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['contacts']['registrant']['email'] + ','
        except (KeyError, TypeError):
            out += 'NA' + ','
        try:
            out += record['contacts']['registrant']['country']
        except (KeyError, TypeError):
            out += 'NA'
            
        return out.lower()
    
    if debug == True: 
        return record
    