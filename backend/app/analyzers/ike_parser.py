import struct
from typing import Dict, Any, List, Optional
from backend.app.analyzers.pcap_parser import PacketMetadata

# Standard IKE Transformation Lookups
ENCRYPTION_ALGORITHMS = {
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "Blowfish-CBC",
    4: "RC5-R16-B64-CBC",
    5: "3DES-CBC",
    6: "CAST-128-CBC",
    7: "AES-CBC",
    8: "Camellia-CBC",
    12: "AES-128-CBC",
    14: "AES-256-CBC",
    18: "AES-128-GCM",
    19: "AES-192-GCM",
    20: "AES-256-GCM",
    28: "CHACHA20-POLY1305"
}

INTEGRITY_ALGORITHMS = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-96",
    6: "HMAC-MD5-128",
    7: "HMAC-SHA1-160",
    8: "AES-CMAC-96",
    12: "HMAC-SHA256-128",
    13: "HMAC-SHA384-192",
    14: "HMAC-SHA512-256"
}

DH_GROUPS = {
    1: "Group 1 (768-bit MODP - Deprecated)",
    2: "Group 2 (1024-bit MODP - Deprecated)",
    5: "Group 5 (1536-bit MODP - Legacy)",
    14: "Group 14 (2048-bit MODP - Secure)",
    15: "Group 15 (3072-bit MODP - Strong)",
    16: "Group 16 (4096-bit MODP - Strong)",
    19: "Group 19 (256-bit ECP - Very Strong)",
    20: "Group 20 (384-bit ECP - Very Strong)",
    21: "Group 21 (521-bit ECP - Very Strong)",
    31: "Group 31 (Curve25519 - Very Strong)"
}

PRF_ALGORITHMS = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512"
}

class IKEParser:
    """
    Decodes and analyzes IKEv1 and IKEv2 exchanges from PCAP UDP payloads.
    """

    @classmethod
    def is_ike_packet(cls, packet: PacketMetadata) -> bool:
        if packet.protocol != "UDP":
            return False
        return (packet.src_port in (500, 4500) or packet.dst_port in (500, 4500))

    @classmethod
    def parse_ike_payload(cls, data: bytes, is_nat_t: bool = False) -> Optional[Dict[str, Any]]:
        """
        Parses raw IKE payload.
        Handles NAT-T Non-ESP marker (4 zero bytes) on port 4500.
        """
        if not data or len(data) < 28:
            return None

        offset = 0
        # If port 4500 and starts with 4 zero bytes, strip Non-ESP marker
        if len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00":
            offset = 4
            is_nat_t = True

        if len(data) - offset < 28:
            return None

        header_bytes = data[offset:offset + 28]
        initiator_spi = header_bytes[:8].hex()
        responder_spi = header_bytes[8:16].hex()
        next_payload = header_bytes[16]
        version_byte = header_bytes[17]
        major_version = (version_byte >> 4) & 0x0F
        minor_version = version_byte & 0x0F
        exchange_type = header_bytes[18]
        flags = header_bytes[19]
        msg_id, total_length = struct.unpack("!II", header_bytes[20:28])

        version_str = f"IKEv{major_version}"
        is_initiator = bool(flags & 0x08)
        is_response = bool(flags & 0x20)

        # Dissect payloads looking for SA proposals
        proposals_info = cls._parse_payloads(data[offset + 28:offset + total_length], next_payload, major_version)

        return {
            "version": version_str,
            "major_version": major_version,
            "minor_version": minor_version,
            "initiator_spi": initiator_spi,
            "responder_spi": responder_spi if responder_spi != "0" * 16 else None,
            "exchange_type": exchange_type,
            "is_initiator": is_initiator,
            "is_response": is_response,
            "message_id": msg_id,
            "nat_traversal": is_nat_t,
            "proposals": proposals_info
        }

    @classmethod
    def _parse_payloads(cls, payload_data: bytes, first_payload_type: int, major_version: int) -> Dict[str, Any]:
        """
        Traverses generic payload chains to extract cryptographic transforms.
        """
        info = {
            "encryption": None,
            "integrity": None,
            "prf": None,
            "dh_group": None,
            "dh_group_num": None,
            "pfs_enabled": False,
            "has_ke": False
        }
        
        curr_offset = 0
        curr_type = first_payload_type

        # Limit depth to prevent malformed infinite loops
        depth = 0
        while curr_offset + 4 <= len(payload_data) and depth < 30:
            depth += 1
            next_payload_type, is_critical, payload_len = payload_data[curr_offset], (payload_data[curr_offset+1] & 0x80) != 0, struct.unpack("!H", payload_data[curr_offset+2:curr_offset+4])[0]
            if payload_len < 4 or curr_offset + payload_len > len(payload_data):
                break
            
            body = payload_data[curr_offset+4:curr_offset+payload_len]

            # Payload Type 33: Security Association (IKEv2) or 1 (IKEv1)
            if (major_version == 2 and curr_type == 33) or (major_version == 1 and curr_type == 1):
                cls._extract_transforms(body, major_version, info)

            # Payload Type 34: Key Exchange (IKEv2)
            elif (major_version == 2 and curr_type == 34) or (major_version == 1 and curr_type == 4):
                info["has_ke"] = True
                if len(body) >= 4:
                    dh_num = struct.unpack("!H", body[:2])[0]
                    if dh_num in DH_GROUPS:
                        info["dh_group_num"] = dh_num
                        info["dh_group"] = DH_GROUPS[dh_num]

            if next_payload_type == 0:
                break
            curr_type = next_payload_type
            curr_offset += payload_len

        return info

    @classmethod
    def _extract_transforms(cls, sa_body: bytes, major_version: int, info: Dict[str, Any]):
        """
        Extracts transforms from Proposal inside SA payload.
        """
        if len(sa_body) < 8:
            return

        # Skip Proposal header to read Transforms
        # IKEv2 Proposal header is 8 bytes
        offset = 8
        while offset + 8 <= len(sa_body):
            last_transform = sa_body[offset]
            transform_len = struct.unpack("!H", sa_body[offset+2:offset+4])[0]
            if transform_len < 8 or offset + transform_len > len(sa_body):
                break
            
            transform_type = sa_body[offset+4]
            transform_id = struct.unpack("!H", sa_body[offset+6:offset+8])[0]

            # Check for Key Length attribute in transform attributes
            attr_offset = offset + 8
            key_len = None
            while attr_offset + 4 <= offset + transform_len:
                attr_type = struct.unpack("!H", sa_body[attr_offset:attr_offset+2])[0]
                is_tv = (attr_type & 0x8000) != 0
                attr_id = attr_type & 0x7FFF
                if is_tv:
                    val = struct.unpack("!H", sa_body[attr_offset+2:attr_offset+4])[0]
                    if attr_id == 14:  # Key Length
                        key_len = val
                    attr_offset += 4
                else:
                    attr_len = struct.unpack("!H", sa_body[attr_offset+2:attr_offset+4])[0]
                    attr_offset += 4 + attr_len

            if transform_type == 1:  # Encryption
                enc_name = ENCRYPTION_ALGORITHMS.get(transform_id, f"ENCR_{transform_id}")
                if key_len:
                    enc_name = f"{enc_name}-{key_len}"
                if not info["encryption"]:
                    info["encryption"] = enc_name
            elif transform_type == 2:  # PRF
                if not info["prf"]:
                    info["prf"] = PRF_ALGORITHMS.get(transform_id, f"PRF_{transform_id}")
            elif transform_type == 3:  # Integrity
                if not info["integrity"]:
                    info["integrity"] = INTEGRITY_ALGORITHMS.get(transform_id, f"AUTH_{transform_id}")
            elif transform_type == 4:  # Diffie-Hellman Group
                if not info["dh_group"]:
                    info["dh_group_num"] = transform_id
                    info["dh_group"] = DH_GROUPS.get(transform_id, f"DH-Group-{transform_id}")

            if last_transform == 0:
                break
            offset += transform_len
