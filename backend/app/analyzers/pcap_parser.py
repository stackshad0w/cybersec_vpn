import os
import struct
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class PacketMetadata:
    timestamp: float
    length: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None  # UDP, ESP, AH, TCP, etc.
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    raw_payload: bytes = field(default=b"", repr=False)

class PCAPParser:
    """
    Validates and parses PCAP and PCAPNG files.
    Extracts packet headers, IKE exchanges, and ESP flows without violating privacy controls.
    """
    PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
    PCAP_MAGIC_NANOSECONDS = 0xa1b23c4d
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    PCAP_MAGIC_SWAPPED_NANO = 0x4d3cb2a1
    PCAPNG_MAGIC = 0x0a0d0d0a

    @classmethod
    def validate_file(cls, file_path: str, max_size_bytes: int = 100 * 1024 * 1024) -> Dict[str, Any]:
        """
        Validates extension, size, and structural magic header bytes.
        """
        if not os.path.exists(file_path):
            return {"valid": False, "error": "File does not exist."}
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {"valid": False, "error": "PCAP file is empty (0 bytes)."}
        if file_size > max_size_bytes:
            return {"valid": False, "error": f"File size ({file_size / 1024 / 1024:.1f} MB) exceeds maximum allowed {max_size_bytes / 1024 / 1024:.0f} MB."}
        
        # Calculate SHA-256
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()

        # Check Magic Bytes
        with open(file_path, "rb") as f:
            magic_bytes = f.read(4)
        
        if len(magic_bytes) < 4:
            return {"valid": False, "error": "File header too short to be a valid capture."}

        magic_int = struct.unpack("!I", magic_bytes)[0]
        file_format = None
        if magic_int in (cls.PCAP_MAGIC_MICROSECONDS, cls.PCAP_MAGIC_NANOSECONDS, cls.PCAP_MAGIC_SWAPPED, cls.PCAP_MAGIC_SWAPPED_NANO):
            file_format = "pcap"
        elif magic_int == cls.PCAPNG_MAGIC:
            file_format = "pcapng"
        else:
            return {
                "valid": False,
                "error": f"Invalid capture magic header bytes: 0x{magic_int:08x}. Supported formats: PCAP (.pcap) and PCAPNG (.pcapng)."
            }

        return {
            "valid": True,
            "format": file_format,
            "size_bytes": file_size,
            "sha256": sha256_hash,
        }

    @classmethod
    def parse_packets(cls, file_path: str) -> List[PacketMetadata]:
        """
        Parses packet metadata using Scapy with fallback to native binary parsing.
        """
        try:
            from scapy.all import rdpcap, IP, IPv6, UDP, TCP, Raw
            packets = rdpcap(file_path)
            results = []
            for pkt in packets:
                ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                pkt_len = len(pkt)
                src_ip, dst_ip, proto = None, None, None
                src_port, dst_port = None, None
                payload = b""

                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto_num = pkt[IP].proto
                    if proto_num == 50:
                        proto = "ESP"
                        payload = bytes(pkt[IP].payload)
                    elif proto_num == 51:
                        proto = "AH"
                        payload = bytes(pkt[IP].payload)
                    elif proto_num == 17:
                        proto = "UDP"
                    elif proto_num == 6:
                        proto = "TCP"
                elif IPv6 in pkt:
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                    proto_num = pkt[IPv6].nh
                    if proto_num == 50:
                        proto = "ESP"
                        payload = bytes(pkt[IPv6].payload)
                    elif proto_num == 51:
                        proto = "AH"
                        payload = bytes(pkt[IPv6].payload)
                    elif proto_num == 17:
                        proto = "UDP"
                    elif proto_num == 6:
                        proto = "TCP"

                if UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    if proto != "ESP" and proto != "AH":
                        proto = "UDP"
                    payload = bytes(pkt[UDP].payload)
                elif TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    if proto is None:
                        proto = "TCP"
                    payload = bytes(pkt[TCP].payload)

                results.append(PacketMetadata(
                    timestamp=ts,
                    length=pkt_len,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    raw_payload=payload
                ))
            return results
        except Exception:
            # Native binary fallback parser for standard pcap
            return cls._parse_native_pcap(file_path)

    @classmethod
    def _parse_native_pcap(cls, file_path: str) -> List[PacketMetadata]:
        packets = []
        try:
            with open(file_path, "rb") as f:
                header = f.read(24)
                if len(header) < 24:
                    return []
                magic = struct.unpack("!I", header[:4])[0]
                is_little_endian = (magic == cls.PCAP_MAGIC_SWAPPED or magic == cls.PCAP_MAGIC_SWAPPED_NANO)
                endian = "<" if is_little_endian else ">"
                
                while True:
                    pkt_hdr = f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                    data = f.read(incl_len)
                    if len(data) < incl_len:
                        break
                    
                    ts = ts_sec + (ts_usec / 1000000.0)
                    src_ip, dst_ip, proto = None, None, None
                    src_port, dst_port = None, None
                    payload = b""

                    # Check Ethernet header (14 bytes)
                    if len(data) >= 14:
                        eth_type = struct.unpack("!H", data[12:14])[0]
                        if eth_type == 0x0800 and len(data) >= 34:  # IPv4
                            ip_hdr = data[14:34]
                            proto_num = ip_hdr[9]
                            src_ip = ".".join(map(str, ip_hdr[12:16]))
                            dst_ip = ".".join(map(str, ip_hdr[16:20]))
                            ip_len = (ip_hdr[0] & 0x0f) * 4
                            ip_payload = data[14 + ip_len:]
                            
                            if proto_num == 50:
                                proto = "ESP"
                                payload = ip_payload
                            elif proto_num == 51:
                                proto = "AH"
                                payload = ip_payload
                            elif proto_num == 17 and len(ip_payload) >= 8:  # UDP
                                proto = "UDP"
                                src_port, dst_port = struct.unpack("!HH", ip_payload[:4])
                                payload = ip_payload[8:]
                            elif proto_num == 6 and len(ip_payload) >= 20:  # TCP
                                proto = "TCP"
                                src_port, dst_port = struct.unpack("!HH", ip_payload[:4])
                                payload = ip_payload[20:]

                    packets.append(PacketMetadata(
                        timestamp=ts,
                        length=orig_len,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=proto,
                        src_port=src_port,
                        dst_port=dst_port,
                        raw_payload=payload
                    ))
        except Exception:
            pass
        return packets
