import time
import threading
from scapy.all import Ether, IP, ICMP, srp, RandMAC, sniff, TCP, ARP
from abc import ABC, abstractmethod
import ipaddress
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

class Output(ABC):
    """Interface for output classes processing PacketSniffer data"""
    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass

i = " " * 4  # Basic indentation

class OutputToScreen(Output):
    def __init__(self, subject, *, display_data: bool, log_file: str = "log.txt", 
                 email_config: dict = None):
        super().__init__(subject)
        self._frame = None
        self._display_data = display_data
        self._log_file = log_file
        self._email_config = email_config or {
            'enabled': True,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'sanjayg122006@gmail.com',
            'sender_password': 'tvjo zhdr hsnx bxbr',
            'recipient_email': 'cghuivbjii@gmail.com'
        }
        self._scan_history = defaultdict(list)
        self._last_alerts = {}
        self._initialize()

    def _initialize(self) -> None:
        print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
              "data. Press Ctrl-C to abort...\n")

    def _send_alert_email(self, alert_type: str, details: dict) -> None:
        """Send email alert in background thread"""
        if not self._email_config.get('enabled', False):
            return

        def _send():
            try:
                # Format email content
                subject = f"🚨 {alert_type} Detected"
                body = (f"{alert_type} detected:\n\n"
                       f"Timestamp: {details['timestamp']}\n"
                       f"Source IP: {details.get('src_ip', 'N/A')}\n"
                       f"Target IP: {details.get('dst_ip', 'N/A')}\n")
                
                if alert_type == "Port Scan":
                    body += (f"Scanned Ports: {details['ports']}\n"
                            f"Total Ports: {details['port_count']}\n")
                elif alert_type == "ARP Spoofing":
                    body += (f"Source MAC: {details['src_mac']}\n"
                            f"Interface: {details['interface']}\n")

                # Create and send email
                msg = MIMEMultipart()
                msg['From'] = self._email_config['sender_email']
                msg['To'] = self._email_config['recipient_email']
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP(
                    self._email_config['smtp_server'],
                    self._email_config['smtp_port']
                ) as server:
                    server.starttls()
                    server.login(
                        self._email_config['sender_email'],
                        self._email_config['sender_password']
                    )
                    server.send_message(msg)
                
                print(f"{i}[+] Email alert sent for {alert_type}")
            except Exception as e:
                print(f"{i}[!] Email failed: {str(e)}")

        threading.Thread(target=_send, daemon=True).start()

    def update(self, frame) -> None:
        self._frame = frame
        try:
            self._display_output_header()
            self._display_protocol_info()
            self._display_packet_contents()
            
            # Run detections in background threads
            threading.Thread(
                target=self._detect_suspicious_activity,
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"{i}[!] Error processing frame: {str(e)}")

    def _detect_suspicious_activity(self):
        """Run all detection methods"""
        current_time = time.time()
        
        # ARP Spoofing Detection
        if 'ARP' in self._frame.protocol_queue:
            self._detect_arp_spoofing(current_time)
        
        # Port Scan Detection
        if 'TCP' in self._frame.protocol_queue:
            self._detect_port_scans(current_time)

    def _detect_arp_spoofing(self, current_time):
        arp = self._frame.arp
        if arp.oper == 1:  # ARP Request
            local_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # Log to file
            with open(self._log_file, "a") as f:
                f.write(
                    f"[{local_time}] Suspicious ARP Request\n"
                    f"    Frame #{self._frame.packet_num}\n"
                    f"    Source MAC: {arp.sha}\n"
                    f"    Source IP: {arp.spa}\n"
                    f"    Target IP: {arp.tpa}\n"
                    f"{'-'*50}\n"
                )
            
            # Send alert
            alert_key = f"arp_{arp.spa}_{arp.tpa}"
            if current_time - self._last_alerts.get(alert_key, 0) > 300:  # 5 min cooldown
                self._send_alert_email("ARP Spoofing", {
                    'timestamp': local_time,
                    'src_ip': arp.spa,
                    'dst_ip': arp.tpa,
                    'src_mac': arp.sha,
                    'interface': getattr(self._frame, 'interface', 'all')
                })
                self._last_alerts[alert_key] = current_time

    def _detect_port_scans(self, current_time):
        tcp = self._frame.tcp
        ipv4 = self._frame.ipv4
        
        src_ip = ipv4.src
        dst_ip = ipv4.dst
        dst_port = tcp.dport
        
        # Only monitor external -> internal
        def is_local(ip):
            try:
                return ipaddress.ip_address(ip).is_private
            except ValueError:
                return False
                
        if is_local(src_ip) or not is_local(dst_ip):
            return
            
        # Update scan history
        key = (src_ip, dst_ip)
        self._scan_history[key].append((current_time, dst_port))
        
        # Remove old entries (>10 sec)
        self._scan_history[key] = [
            (t, p) for t, p in self._scan_history[key]
            if current_time - t <= 10
        ]
        
        # Get unique ports
        ports = {p for t, p in self._scan_history[key]}
        common_ports = {80, 443, 8080, 8443}
        filtered_ports = [p for p in ports if p not in common_ports]
        
        if len(filtered_ports) >= 15:  # Lowered threshold for testing
            local_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            sorted_ports = sorted(filtered_ports)
            
            # Log to file
            with open(self._log_file, "a") as f:
                f.write(
                    f"[{local_time}] Port Scan Detected\n"
                    f"    Source: {src_ip}\n"
                    f"    Target: {dst_ip}\n"
                    f"    Ports: {sorted_ports}\n"
                    f"{'-'*50}\n"
                )
            
            # Send alert
            alert_key = f"scan_{src_ip}_{dst_ip}"
            if current_time - self._last_alerts.get(alert_key, 0) > 600:  # 10 min cooldown
                self._send_alert_email("Port Scan", {
                    'timestamp': local_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ports': sorted_ports,
                    'port_count': len(filtered_ports)
                })
                self._last_alerts[alert_key] = current_time

    # [Keep all your existing display methods unchanged...]
    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}:")

    def _display_protocol_info(self) -> None:
        for proto in self._frame.protocol_queue:
            try:
                getattr(self, f"_display_{proto.lower()}_data")()
            except AttributeError:
                print(f"{'':>4}[+] Unknown Protocol")

    # [Include all other _display_* methods from your original code]
    # ...

    def _display_ethernet_data(self) -> None:
        ethernet = self._frame.ethernet
        interface = "all" if self._frame.interface is None else self._frame.interface
        frame_length: int = self._frame.frame_length
        epoch_time: float = self._frame.epoch_time
        print(f"{i}[+] Ethernet {ethernet.src:.>23} -> {ethernet.dst}")
        print(f"{2 * i}  Interface: {interface}")
        print(f"{2 * i}  Frame Length: {frame_length}")
        print(f"{2 * i}  Epoch Time: {epoch_time}")

    def _display_ipv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        print(f"{i}[+] IPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * i}  DSCP: {ipv4.dscp}")
        print(f"{2 * i}  Total Length: {ipv4.len}")
        print(f"{2 * i}  ID: {ipv4.id}")
        print(f"{2 * i}  Flags: {ipv4.flags_str}")
        print(f"{2 * i}  TTL: {ipv4.ttl}")
        print(f"{2 * i}  Protocol: {ipv4.encapsulated_proto}")
        print(f"{2 * i}  Header Checksum: {ipv4.chksum_hex_str}")

    def _display_ipv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        print(f"{i}[+] IPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * i}  Traffic Class: {ipv6.tclass_hex_str}")
        print(f"{2 * i}  Flow Label: {ipv6.flabel_txt_str}")
        print(f"{2 * i}  Payload Length: {ipv6.payload_len}")
        print(f"{2 * i}  Next Header: {ipv6.encapsulated_proto}")
        print(f"{2 * i}  Hop Limit: {ipv6.hop_limit}")

    def _display_arp_data(self) -> None:
        arp = self._frame.arp
        if arp.oper == 1:
            print(f"{i}[+] ARP Who has {arp.tpa:.>18} ? -> Tell {arp.spa}")
        else:
            print(f"{i}[+] ARP {arp.spa:.>28} -> Is at {arp.sha}")
        print(f"{2 * i}  Hardware Type: {arp.htype}")
        print(f"{2 * i}  Protocol Type: {arp.ptype_str} ({arp.ptype_hex_str})")
        print(f"{2 * i}  Hardware Length: {arp.hlen}")
        print(f"{2 * i}  Protocol Length: {arp.plen}")
        print(f"{2 * i}  Operation: {arp.oper} ({arp.oper_str})")
        print(f"{2 * i}  Sender Hardware Address: {arp.sha}")
        print(f"{2 * i}  Sender Protocol Address: {arp.spa}")
        print(f"{2 * i}  Target Hardware Address: {arp.tha}")
        print(f"{2 * i}  Target Protocol Address: {arp.tpa}")

    def _display_tcp_data(self) -> None:
        tcp = self._frame.tcp
        print(f"{i}[+] TCP {tcp.sport:.>28} -> {tcp.dport: <15}")
        print(f"{2 * i}  Sequence Number: {tcp.seq}")
        print(f"{2 * i}  ACK Number: {tcp.ack}")
        print(f"{2 * i}  Flags: {tcp.flags_hex_str} > {tcp.flags_str}")
        print(f"{2 * i}  Window Size: {tcp.window}")
        print(f"{2 * i}  Checksum: {tcp.chksum_hex_str}")
        print(f"{2 * i}  Urgent Pointer: {tcp.urg}")

    def _display_udp_data(self) -> None:
        udp = self._frame.udp
        print(f"{i}[+] UDP {udp.sport:.>28} -> {udp.dport}")
        print(f"{2 * i}  Header Length: {udp.len}")
        print(f"{2 * i}  Header Checksum: {udp.chksum}")

    def _display_icmpv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        icmpv4 = self._frame.icmpv4
        print(f"{i}[+] ICMPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * i}  ICMP Type: {icmpv4.type} ({icmpv4.type_str})")
        print(f"{2 * i}  Header Checksum: {icmpv4.chksum_hex_str}")

    def _display_icmpv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        icmpv6 = self._frame.icmpv6
        print(f"{i}[+] ICMPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * i}  Control Message Type: {icmpv6.type} ({icmpv6.type_str})")
        print(f"{2 * i}  Control Message Subtype: {icmpv6.code}")
        print(f"{2 * i}  Header Checksum: {icmpv6.chksum_hex_str}")

    def _display_packet_contents(self) -> None:
        if self._display_data is True:
            print(f"{i}[+] DATA:")
            data = (self._frame.data.decode(errors="ignore").
                    replace("\n", f"\n{i * 2}"))
            print(f"{i}{data}")




#detection of promiscuous Sniffer in the network
    # def _detect_promiscuous_sniffer_probe(self,interface="wlo1", fake_ip="192.168.100.200", real_ip="192.168.100.1"):
    #     """
    #     Sends a fake packet to detect sniffers in promiscuous mode.
    #     Any response indicates a possible sniffer.
    #     """
    #     fake_mac = str(RandMAC())

    #     print(f"[+] Sending sniffing-detection probe to {fake_ip} with fake MAC {fake_mac}...")
    #     packet = Ether(dst=fake_mac) / IP(dst=fake_ip, src=real_ip) / ICMP()

    #     try:
    #         ans, _ = srp(packet, iface=interface, timeout=3, verbose=0)
    #         if ans:
    #             print("[🚨] WARNING: Sniffer detected! Someone responded to a fake MAC/IP combo!")
    #             for snd, rcv in ans:
    #                 print(f"Sniffer IP: {rcv[IP].src} | MAC: {rcv.src}")
    #         else:
    #             print("[✔️] No sniffers detected on the network.")
    #     except Exception as e:
    #         print(f"[ERROR] Failed to detect sniffers: {str(e)}")