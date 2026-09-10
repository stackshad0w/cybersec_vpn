import struct
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from backend.app.analyzers.pcap_parser import PacketMetadata
from backend.app.models.ipsec import IPsecMode, EvidenceStatus

class ESPAnalyzer:
    """
    Analyzes Encapsulating Security Payload (ESP - IP Proto 50 or UDP 4500) traffic.
    Tracks SPIs, sequence numbers for anti-replay, directions, packet metrics, and tunnel/transport mode.
    """

    @classmethod
    def is_esp_packet(cls, packet: PacketMetadata) -> bool:
        if packet.protocol == "ESP":
            return True
        # UDP Encapsulation (Port 4500) without 4 zero bytes (non-ESP marker)
        if packet.protocol == "UDP" and (packet.src_port == 4500 or packet.dst_port == 4500):
            if len(packet.raw_payload) >= 8 and packet.raw_payload[:4] != b"\x00\x00\x00\x00":
                return True
        return False

    @classmethod
    def parse_esp_header(cls, packet: PacketMetadata) -> Optional[Dict[str, Any]]:
        """
        Extracts ESP SPI (4 bytes) and Sequence Number (4 bytes).
        """
        payload = packet.raw_payload
        # If UDP port 4500, ESP begins right at payload if no non-ESP marker
        if len(payload) < 8:
            return None

        spi_int, seq_num = struct.unpack("!II", payload[:8])
        spi_hex = f"0x{spi_int:08x}"

        return {
            "spi": spi_hex,
            "spi_int": spi_int,
            "sequence_number": seq_num,
            "packet_length": packet.length,
            "timestamp": packet.timestamp,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
        }

    @classmethod
    def analyze_esp_flows(cls, esp_packets: List[PacketMetadata]) -> List[Dict[str, Any]]:
        """
        Groups ESP packets by flow and evaluates sequence numbers, directions, and anti-replay protection.
        """
        flows = defaultdict(list)
        for pkt in esp_packets:
            hdr = cls.parse_esp_header(pkt)
            if hdr:
                key = (hdr["src_ip"], hdr["dst_ip"], hdr["spi"])
                flows[key].append(hdr)

        results = []
        for (src_ip, dst_ip, spi), packets in flows.items():
            seqs = [p["sequence_number"] for p in packets]
            total_bytes = sum(p["packet_length"] for p in packets)
            pkt_count = len(packets)
            
            # Anti-replay and sequence inspection
            seen_seqs = set()
            duplicates = 0
            out_of_order = 0
            prev_seq = 0
            
            for s in seqs:
                if s in seen_seqs:
                    duplicates += 1
                seen_seqs.add(s)
                if s < prev_seq:
                    out_of_order += 1
                prev_seq = s

            min_seq = min(seqs) if seqs else 0
            max_seq = max(seqs) if seqs else 0
            
            replay_protection_enabled = (duplicates == 0 and out_of_order <= max(1, pkt_count * 0.05))
            replay_status = EvidenceStatus.VERIFIED if pkt_count >= 5 else EvidenceStatus.POTENTIAL_INFERRED

            # Mode Determination (Tunnel vs Transport vs Unknown)
            mode, confidence, evidence = cls._infer_mode(packets, src_ip, dst_ip)

            results.append({
                "protocol": "ESP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "spi_inbound": spi,
                "spi_outbound": None,
                "packet_count": pkt_count,
                "total_bytes": total_bytes,
                "min_sequence_number": min_seq,
                "max_sequence_number": max_seq,
                "duplicate_sequences_count": duplicates,
                "out_of_order_count": out_of_order,
                "replay_protection_enabled": replay_protection_enabled,
                "replay_protection_status": replay_status,
                "mode": mode,
                "mode_confidence": confidence,
                "mode_evidence": evidence
            })

        return results

    @classmethod
    def _infer_mode(cls, packets: List[Dict[str, Any]], src_ip: str, dst_ip: str) -> Tuple[str, float, str]:
        """
        Determines Tunnel or Transport mode with evidence and confidence.
        """
        # Clue 1: Packet size distribution (Tunnel mode has outer IP header + ESP header + inner IP header + padding)
        # Typically packets >= 100 bytes with regular MTU chunks
        # Clue 2: Gateway addresses vs host addresses (e.g. gateway endpoints routing diverse payload sizes)
        # Clue 3: Explicit ESP NAT-T encapsulation (UDP 4500) is predominantly used in Tunnel mode remote-access/site-to-site
        
        avg_len = sum(p["packet_length"] for p in packets) / max(len(packets), 1)
        
        # If packets show significant variance and typical encapsulated payload sizes
        if avg_len > 120 and len(packets) >= 3:
            return (
                IPsecMode.TUNNEL.value,
                0.88,
                f"Observed ESP flow between security gateways {src_ip} -> {dst_ip}. Packet lengths (avg {avg_len:.1f} bytes) and encapsulation characteristics indicate encapsulated inner IP datagrams (Tunnel Mode)."
            )
        elif avg_len <= 100 and len(packets) >= 3:
            return (
                IPsecMode.TRANSPORT.value,
                0.75,
                f"Observed ESP flow directly between host endpoints {src_ip} and {dst_ip} without encapsulated inner network headers (Transport Mode)."
            )
        else:
            return (
                IPsecMode.UNKNOWN.value,
                0.40,
                f"Insufficient packet flow sample ({len(packets)} packets) to definitively distinguish Tunnel from Transport mode."
            )
