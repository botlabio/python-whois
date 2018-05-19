import socket, re, sys, requests
from codecs import encode, decode
from . import shared
from .parse import parse_raw_whois

session = requests.Session()
response = session.get('https://raw.githubusercontent.com/botlabio/logly/master/logly/cc_tld.txt')
cc_tld = response.text.splitlines()

response = session.get('https://raw.githubusercontent.com/botlabio/logly/master/logly/tld_level_whois.txt')
tld_nic = response.text.splitlines()

cc = [i.split(',')[0] for i in tld_nic]
cc_whois = [i.split(',')[1] for i in tld_nic]

def get_reg_whois(domain):

	temp = get_whois_raw(domain)
	return parse_raw_whois(temp)['whois_server'][0]


def get_root_server(domain, server="whois.iana.org"):

    # get the record first
    data = whois_request(domain, server)
    
    # try to find it from the record
    for line in [x.strip() for x in data.splitlines()]:	
        match = re.match("refer:\s*([^\s]+)", line)
        if match is None:
            continue
        else:
            return match.group(1)
        
    # case where no result was found
    tld = domain.split('.')[-1]
    return cc_whois[cc.index(tld)]
        
    # or then raise error if nothing worked
    error_string = "No root whois found for " + str(domain)
    raise shared.WhoisException(error_string)


def get_whois_raw(domain, server=None, rfc3490=True, never_cut=False, with_server_list=False, server_list=None):
	
	'''Gets the raw data for the domain'''

	server_list = server_list or []
	# Sometimes IANA simply won't give us the right root WHOIS server
	
	if rfc3490:
		if sys.version_info < (3, 0):
			domain = encode( domain if type(domain) is unicode else decode(domain, "utf8"), "idna" )
		else:
			domain = encode(domain, "idna").decode("ascii")

	if server is None:
		target_server = get_root_server(domain)
	elif '.' + domain.split('.')[-1] in cc_tld:
		target_server = get_root_server(domain)
		print('Country Names no user server')
	else:
		target_server = server
		



	# deal with japanese case
	if target_server == "whois.jprs.jp":
		request_domain = "%s/e" % domain # Suppress Japanese output
	
	# deal with germany case
	elif domain.endswith(".de") and ( target_server == "whois.denic.de" or target_server == "de.whois-servers.net" ):
		request_domain = "-T dn,ace %s" % domain # regional specific stuff
	
	# deal with verisign
	elif target_server == "whois.verisign-grs.com":
		request_domain = "=%s" % domain # Avoid partial matches
	
	# all other cases
	else:
		request_domain = domain

	# decide on the 
	response = whois_request(request_domain, target_server)
	
	# gives the whole raw data in return
	if never_cut:
		new_list = [response]
	# deal with verisign separately
	if target_server == "whois.verisign-grs.com":
		for record in response.split("\n\n"):
			if re.search("Domain Name: %s\n" % domain.upper(), record):
				response = record
				break

	if never_cut == False:
		new_list = [response]
	
	server_list.append(target_server)

	for line in [x.strip() for x in response.splitlines()]:
		match = re.match("(refer|whois server|referral url|whois server|registrar whois):\s*([^\s]+\.[^\s]+)", line, re.IGNORECASE)
		if match is not None:
			referal_server = match.group(2)
			if referal_server != server and "://" not in referal_server: # We want to ignore anything non-WHOIS (eg. HTTP) for now.
				# Referal to another WHOIS server...
				return get_whois_raw(domain, referal_server, new_list, server_list=server_list, with_server_list=with_server_list)
	if with_server_list:
		return (new_list, server_list)
	else:
		return new_list
	
	
def whois_request(domain, server, port=43):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((server, port))
		sock.send(("%s\r\n" % domain).encode("utf-8"))
		buff = b""
		while True:
			data = sock.recv(1024)
			if len(data) == 0:
				break
			buff += data
		return buff.decode("latin-1")
	except (ConnectionRefusedError, ConnectionResetError):
		return 'NA'
