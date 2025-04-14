import sys
import base64
import socket
import datetime
from dnslib import DNSRecord


def Decode(encoded_msg):
	variants = [encoded_msg, encoded_msg + "=", encoded_msg + "=="]
	for variant in variants:
		try:
			decoded_msg = base64.b64decode(variant)
			decoded_string = decoded_msg.decode("utf-8")
			return decoded_string
		except Exception:
			continue
	return "<Decoding failed>"


def listener(ns_subdomain):
	server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server.bind(('0.0.0.0', 53))
	print("Monitoring DNS queries for subdomain " + ns_subdomain)

	subdomain_entries = []
	while True:
		data, addr = server.recvfrom(4096)
		d = DNSRecord.parse(data)
		subdomain = str(d.questions[0]._qname).split(ns_subdomain)[0]

		if '-' in subdomain:
	        	prefix, content = subdomain.split('-', 1)
		        if prefix.isdigit():
		            prefix = int(prefix)
		            if prefix == 0 and subdomain not in subdomain_entries:
		                subdomain_entries = []
		            if subdomain not in subdomain_entries:
		                subdomain_entries.append(subdomain)
		                sorted_entries = sorted(subdomain_entries, key=lambda x: int(x.split('-')[0]))
	        	        all_subdomain = "".join(x.split('-', 1)[1] for x in sorted_entries)
	                	print("Received values: " + str(subdomain_entries))
	        	        print("Decoded value:   " + str(Decode(all_subdomain)))


def main():
	listener(sys.argv[1])


if __name__== "__main__":
	main()
