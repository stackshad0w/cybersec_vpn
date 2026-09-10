import os
import sys
import struct
from pathlib import Path

# Ensure root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scapy.all import Ether, IP, UDP, Raw, wrpcap

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "pcaps"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def build_ike_sa_init_packet(
    src_ip: str,
    dst_ip: str,
    initiator_spi: bytes,
    responder_spi: bytes,
    major_version: int,
    enc_id: int,
    integ_id: int,
    dh_group: int,
    is_nat_t: bool = False
):
    """
    Constructs an authentic IKE header and SA proposal payload.
    """
    # Transform format: Last(B), Res(B), TransLen(H), Type(B), Res(B), TransID(H) -> "!BBHBBH"
    trans_enc = struct.pack("!BBHBBH", 3, 0, 8, 1, 0, enc_id)
    trans_prf = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 5)  # PRF_SHA256
    trans_integ = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)
    trans_dh = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_group)

    transforms = trans_enc + trans_prf + trans_integ + trans_dh

    # Proposal header: Last(B), Res(B), PropLen(H), PropNum(B), ProtoID(B), SPISize(B), NumTransforms(B) -> "!BBHBBBB"
    prop_hdr = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4)
    proposal_data = prop_hdr + transforms

    # SA Payload header: NextPayload(B), Critical(B), PayloadLen(H)
    sa_payload_type = 33 if major_version == 2 else 1
    sa_hdr = struct.pack("!BBH", 0, 0, 4 + len(proposal_data))
    sa_body = sa_hdr + proposal_data

    # IKE Header: InitSPI(8), RespSPI(8), NextPayload(1), Version(1), Exchange(1), Flags(1), MsgID(4), Length(4)
    ver_byte = (major_version << 4) | 0
    exchange_type = 34 if major_version == 2 else 2  # IKE_SA_INIT vs Identity Protection
    flags = 0x08  # Initiator
    msg_id = 0
    total_len = 28 + len(sa_body)

    ike_hdr = initiator_spi + responder_spi + struct.pack("!BBBBII", sa_payload_type, ver_byte, exchange_type, flags, msg_id, total_len)
    ike_data = ike_hdr + sa_body

    if is_nat_t:
        # Prepend Non-ESP Marker (4 bytes 0x00) for UDP 4500
        ike_data = b"\x00\x00\x00\x00" + ike_data
        sport, dport = 4500, 4500
    else:
        sport, dport = 500, 500

    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=ike_data)
    return pkt

def build_esp_packet(src_ip: str, dst_ip: str, spi_int: int, seq_num: int, payload_size: int, is_nat_t: bool = False):
    """
    Constructs an ESP packet with valid SPI and Sequence Number.
    """
    # ESP Header: SPI (4 bytes), Sequence Number (4 bytes)
    esp_hdr = struct.pack("!II", spi_int, seq_num)
    # Mock encrypted payload
    encrypted_data = b"\xaa" * max(16, payload_size - 8)
    esp_data = esp_hdr + encrypted_data

    if is_nat_t:
        # UDP Encapsulation port 4500 (No Non-ESP marker for ESP traffic)
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=esp_data)
    else:
        # Native IP Protocol 50 (ESP)
        pkt = Ether() / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=esp_data)
    return pkt

def generate_testbed_pcaps():
    print("Generating reproducible testbed PCAPs...")

    # Case 1: Secure Case (IKEv2 + Tunnel + AES-256-GCM + DH-19 + PFS ON + Replay ON)
    packets_secure = []
    base_time = 1700000000.0
    ike_pkt = build_ike_sa_init_packet(
        src_ip="203.0.113.10", dst_ip="198.51.100.20",
        initiator_spi=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        responder_spi=b"\x00" * 8,
        major_version=2,
        enc_id=20,     # AES-256-GCM
        integ_id=12,   # HMAC-SHA256
        dh_group=19,   # Group 19 (ECP-256)
        is_nat_t=True
    )
    ike_pkt.time = base_time
    packets_secure.append(ike_pkt)

    # Add ESP packets with monotonic sequence numbers (1 to 50)
    t = base_time + 0.1
    for seq in range(1, 51):
        esp = build_esp_packet("203.0.113.10", "198.51.100.20", 0x1a2b3c4d, seq, 1200, is_nat_t=True)
        esp.time = t
        packets_secure.append(esp)
        t += 0.02

    path_secure = OUTPUT_DIR / "secure_ikev2_tunnel.pcap"
    wrpcap(str(path_secure), packets_secure)
    print(f"Generated {path_secure} ({len(packets_secure)} packets)")

    # Case 2: Weak Case (IKEv1 + 3DES-CBC + MD5 + DH Group 2 + Replay violations)
    packets_weak = []
    t = base_time
    ike_weak = build_ike_sa_init_packet(
        src_ip="192.168.1.50", dst_ip="192.168.1.1",
        initiator_spi=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11",
        responder_spi=b"\x00" * 8,
        major_version=1,
        enc_id=5,      # 3DES-CBC
        integ_id=1,    # HMAC-MD5-96
        dh_group=2,    # Group 2 (1024-bit deprecated)
        is_nat_t=False
    )
    ike_weak.time = t
    packets_weak.append(ike_weak)

    t += 0.1
    # ESP packets with duplicate sequences (replay attack simulation)
    seqs = [1, 2, 3, 4, 2, 5, 6, 7, 3, 8, 9, 10]
    for s in seqs:
        esp = build_esp_packet("192.168.1.50", "192.168.1.1", 0x99887766, s, 320, is_nat_t=False)
        esp.time = t
        packets_weak.append(esp)
        t += 0.05

    path_weak = OUTPUT_DIR / "weak_ikev1_tunnel.pcap"
    wrpcap(str(path_weak), packets_weak)
    print(f"Generated {path_weak} ({len(packets_weak)} packets)")

    # Case 3: Transport Mode (Direct host-to-host ESP with small packets)
    packets_transport = []
    t = base_time
    for seq in range(1, 30):
        esp = build_esp_packet("10.0.0.5", "10.0.0.12", 0x44556677, seq, 88, is_nat_t=False)
        esp.time = t
        packets_transport.append(esp)
        t += 0.03

    path_transport = OUTPUT_DIR / "transport_gcm.pcap"
    wrpcap(str(path_transport), packets_transport)
    print(f"Generated {path_transport} ({len(packets_transport)} packets)")

    # Case 4: Demo Target Video (IKEv2, Tunnel, AES-256-GCM, DH-19, Video traffic pattern)
    packets_demo = []
    t = base_time
    ike_demo = build_ike_sa_init_packet(
        src_ip="203.0.113.15", dst_ip="198.51.100.4",
        initiator_spi=b"\xa4\xf2\x10\xd3\xe5\xb7\x89\x12",
        responder_spi=b"\x00" * 8,
        major_version=2,
        enc_id=20,    # AES-256-GCM
        integ_id=12,  # SHA-256
        dh_group=19,  # Group 19
        is_nat_t=True
    )
    ike_demo.time = t
    packets_demo.append(ike_demo)

    t += 0.05
    # Generate high bandwidth video chunks
    for seq in range(1, 120):
        size = 1420 if seq % 8 != 0 else 240
        esp = build_esp_packet("203.0.113.15", "198.51.100.4", 0x7f3a910c, seq, size, is_nat_t=True)
        esp.time = t
        packets_demo.append(esp)
        t += 0.005  # fast video burst

    path_demo = OUTPUT_DIR / "demo_target_video.pcap"
    wrpcap(str(path_demo), packets_demo)
    print(f"Generated {path_demo} ({len(packets_demo)} packets)")

    # Copy demo pcap into uploads directory for immediate backend access
    uploads_demo_path = Path(__file__).resolve().parent.parent.parent / "uploads" / "demo_enterprise_vpn_ikev2_aes_gcm_demo.pcapng"
    uploads_demo_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(uploads_demo_path), packets_demo)
    print(f"Copied demo pcap to {uploads_demo_path}")

if __name__ == "__main__":
    generate_testbed_pcaps()
