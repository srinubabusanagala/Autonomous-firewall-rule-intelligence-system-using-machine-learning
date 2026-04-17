import queue
import threading
import time
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

def capture_live(interface=None):
    """
    Capture live packets and yield clean packet dictionaries
    """
    packet_queue = queue.Queue()

    def process_packet(pkt):
        packet = {
            "timestamp": time.time(),
            "src_ip": "",
            "dst_ip": "",
            "protocol": "",
            "src_port": 0,
            "dst_port": 0,
            "length": len(pkt)
        }

        has_ip = False
        if IP in pkt:
            packet["src_ip"] = pkt[IP].src
            packet["dst_ip"] = pkt[IP].dst
            has_ip = True
        elif IPv6 in pkt:
            packet["src_ip"] = pkt[IPv6].src
            packet["dst_ip"] = pkt[IPv6].dst
            has_ip = True

        if has_ip:
            if TCP in pkt:
                packet["protocol"] = "tcp"
                packet["src_port"] = int(pkt[TCP].sport)
                packet["dst_port"] = int(pkt[TCP].dport)
            elif UDP in pkt:
                packet["protocol"] = "udp"
                packet["src_port"] = int(pkt[UDP].sport)
                packet["dst_port"] = int(pkt[UDP].dport)
            else:
                packet["protocol"] = "ip"
            return packet

        return None

    def packet_callback(pkt):
        parsed = process_packet(pkt)
        if parsed:
            packet_queue.put(parsed)

    def start_sniffing():
        try:
            iface_to_sniff = interface
            if iface_to_sniff is None:
                try:
                    iface_to_sniff = conf.route.route("0.0.0.0")[0]
                except Exception:
                    pass
            sniff(iface=iface_to_sniff, prn=packet_callback, store=0)
        except Exception as e:
            print(f"[Sniffer Error] {e}")

    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    while True:
        try:
            yield packet_queue.get(timeout=1.0)
        except queue.Empty:
            continue
