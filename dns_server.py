import sys
import base64
import socket
from datetime import datetime
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


def listener(ns_subdomain, file_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('0.0.0.0', 53))
    print("Monitoring DNS queries for subdomain " + ns_subdomain)

    subdomain_entries = []
    while True:
        data, addr = server.recvfrom(4096)
        d = DNSRecord.parse(data)
        subdomain = str(d.questions[0]._qname).split(ns_subdomain)[0]
        #print(subdomain)

        if '-' in subdomain:
            try:
                prefix, content = subdomain.split('-', 1)
                if prefix.isdigit():
                    prefix = int(prefix)
                    if prefix == 0 and subdomain not in subdomain_entries:
                        subdomain_entries = []
                    if subdomain not in subdomain_entries:
                        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        logging_line = timestamp_str + " Subdomain: " + subdomain + "\n"
                        with open(file_path, "a") as file:
                            file.write(logging_line)

                        subdomain_entries.append(subdomain)
                        sorted_entries = sorted(subdomain_entries, key=lambda x: int(x.split('-')[0]))
                        all_subdomain = "".join(x.split('-', 1)[1] for x in sorted_entries)
                        print("Received values: " + str(subdomain_entries))

                        decoded_value = str(Decode(all_subdomain))
                        if decoded_value != "<Decoding failed>":
                            logging_line = timestamp_str + " Decoded:   " + decoded_value + "\n"
                            with open(file_path, "a") as file:
                                file.write(logging_line)

                        print("Decoded value:   " + decoded_value)
            except Exception as e:
                print("Error parsing subdomain:", e)


def main():
    listener(sys.argv[1], "log.txt")


if __name__ == "__main__":
    main()

