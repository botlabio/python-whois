from .net import get_reg_whois, get_whois_raw
from .parse import parse_raw_whois

def get_records(domain, debug=False):

    try:
        server = get_reg_whois(domain)
    except:
        server = None

    raw = get_whois_raw(domain, server=server, whois_timeout=5)

    record = parse_raw_whois(raw)

    if debug == False:

        out = domain + ','

        try:
            out += record['creation_date'][0].strftime("%Y") + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += record['expiration_date'][0].strftime("%Y") + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += record['nameservers'][0] + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += record['nameservers'][1] + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += '"' + record['registrar'][0] + '"' + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += '"' + record['contacts']['registrant']['organization'] + '"' + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += '"' + record['contacts']['registrant']['name'] + '"' + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += record['contacts']['registrant']['email'] + ','
        except (KeyError, TypeError, IndexError):
            out += 'NA' + ','
        try:
            out += record['contacts']['registrant']['country']
        except (KeyError, TypeError, IndexError):
            out += 'NA'

        return out.lower()

    if debug == True:
        return record
