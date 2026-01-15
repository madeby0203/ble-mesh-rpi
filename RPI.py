#!/usr/bin/python 
import os
import platform
import sys
import time
import uuid
import hashlib
from binascii import hexlify

# Crypto dependencies
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC, SHA256

# extra libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.fields import *
from struct import pack, unpack
from scapy.compat import raw
from timeout_lib import start_timeout, disable_timeout

# --- Cryptography Helper Functions ---
def s1(m):
    return CMAC.new(b'\x00'*16, ciphermod=AES).update(m).digest()

def k1(n, salt, p):
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    return CMAC.new(t, ciphermod=AES).update(p).digest()

def prsk(salt, p):
    return k1(b'prsk', salt, p)

def prsn(salt, p):
    return k1(b'prsn', salt, p)

def prck(salt, p):
    return k1(b'prck', salt, p)

def prdk(salt, p):
    return k1(b'prdk', salt, p)

# k2 function to derive network security material (NID, encryption key, privacy key)
def k2(netkey, p_value):
    """
    Derive network security material from network key using k2.
    Returns: (nid, encryption_key, privacy_key)
    """
    # Salt = s1("smk2")
    salt = s1(b'smk2')
    
    # T = AES-CMAC_Salt(NetKey)
    t = CMAC.new(salt, ciphermod=AES).update(netkey).digest()
    
    # T1 = AES-CMAC_T(T0 || P || 0x01) where T0 is empty
    # NID = T1[15] & 0x7F
    tmp = bytearray(p_value + b'\x01')
    t1 = CMAC.new(t, ciphermod=AES).update(tmp).digest()
    nid = t1[15] & 0x7F
    
    # T2 = AES-CMAC_T(T1 || P || 0x02)
    # EncryptionKey = T2
    tmp = bytearray(t1 + p_value + b'\x02')
    encryption_key = CMAC.new(t, ciphermod=AES).update(tmp).digest()
    
    # T3 = AES-CMAC_T(T2 || P || 0x03)
    # PrivacyKey = T3
    tmp = bytearray(encryption_key + p_value + b'\x03')
    privacy_key = CMAC.new(t, ciphermod=AES).update(tmp).digest()
    
    return nid, encryption_key, privacy_key

# --- Custom Scapy Class Definitions ---
class EIR_Element(Packet):
    name = "EIR Element"
    fields_desc = [
        FieldLenField("len", None, "data", "B", 1),
        ByteEnumField("type", 0, {0x16: "service_data_16_bit_uuid"}),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 1)
    ]
    def extract_padding(self, s):
        return self.data, None

class EIR_Service_Data_16_bit_UUID(EIR_Element):
    name = "EIR - Service Data - 16-bit UUID"
    fields_desc = [
        ByteEnumField("type", 0x16, {0x16: "service_data_16_bit_uuid"}),
        ShortField("uuid", 0),
        StrLenField("servicedata", "", length_from=lambda pkt: pkt.len - 3)
    ]

class ATT_Read_Rsp(Packet):
    name = "ATT Read Response"
    fields_desc = [ StrField("value", None) ]

class ATT_Write_Rsp(Packet):
    name = "ATT Write Response"
    fields_desc = []

class ATT_Handle_Value_Notification(Packet):
    name = "ATT Handle Value Notification"
    fields_desc = [ ShortField("handle", 0), StrField("value", "") ]

class ATT_Exchange_MTU_Rsp(Packet):
    name = "ATT Exchange MTU Response"
    fields_desc = [ShortField("mtu", 23)]

class ATT_Read_By_Group_Type_Rsp(Packet):
    name = "ATT Read By Group Type Response"
    fields_desc = [ByteField("length", 0), StrField("data", "")]

class ATT_Read_By_Type_Rsp(Packet):
    name = "ATT Read By Type Response"
    fields_desc = [ByteField("length", 0), StrField("data", "")]

class ATT_Find_Information_Rsp(Packet):
    name = "ATT Find Information Response"
    fields_desc = [ByteField("format", 0), StrField("data", "")]

class ATT_Error_Rsp(Packet):
    name = "ATT Error Response"
    fields_desc = [ByteField("request", 0), ShortField("handle", 0), ByteField("ecode", 0)]

# Bindings can be unreliable, but included for clarity
bind_layers(ATT_Hdr, ATT_Read_Rsp, opcode=0x0b)
bind_layers(ATT_Hdr, ATT_Write_Rsp, opcode=0x13)
bind_layers(ATT_Hdr, ATT_Handle_Value_Notification, opcode=0x1b)
bind_layers(ATT_Hdr, ATT_Exchange_MTU_Rsp, opcode=0x03)
bind_layers(ATT_Hdr, ATT_Read_By_Group_Type_Rsp, opcode=0x11)
bind_layers(ATT_Hdr, ATT_Read_By_Type_Rsp, opcode=0x09)
bind_layers(ATT_Hdr, ATT_Find_Information_Rsp, opcode=0x05)
bind_layers(ATT_Hdr, ATT_Error_Rsp, opcode=0x01)

# --- Mesh PDU Definitions ---
class MeshProxyPDU(Packet):
    name = "Mesh Proxy PDU"
    fields_desc = [
        BitField("sar", 0, 2),
        BitEnumField("type", 3, 6, {3: "provisioning_pdu"})
    ]

class MeshProvisioningInvite(Packet):
    name = "Mesh Provisioning Invite"
    fields_desc = [ByteField("opcode", 0x00), ByteField("attention_duration", 0x05)]

class MeshProvisioningCapabilities(Packet):
    name = "Mesh Provisioning Capabilities"
    fields_desc = [
        ByteField("opcode", 0x01), ByteField("num_elements", 1), ShortField("algorithms", 0x0001),
        ByteField("pub_key_type", 0), ByteField("static_oob_type", 0), ByteField("output_oob_size", 0),
        ShortField("output_oob_action", 0), ByteField("input_oob_size", 0), ShortField("input_oob_action", 0)
    ]

class MeshProvisioningStart(Packet):
    name = "Mesh Provisioning Start"
    fields_desc = [
        ByteField("opcode", 0x02), ByteField("algorithm", 0), ByteField("pub_key", 0),
        ByteField("auth_method", 0), ByteField("auth_action", 0), ByteField("auth_size", 0)
    ]

class MeshProvisioningPublicKey(Packet):
    name = "Mesh Provisioning Public Key"
    fields_desc = [ ByteField("opcode", 0x03), StrFixedLenField("key", b'\x00'*64, 64) ]

class MeshProvisioningConfirmation(Packet):
    name = "Mesh Provisioning Confirmation"
    fields_desc = [ ByteField("opcode", 0x05), StrFixedLenField("confirmation", b'\x00'*16, 16) ]

class MeshProvisioningRandom(Packet):
    name = "Mesh Provisioning Random"
    fields_desc = [ ByteField("opcode", 0x06), StrFixedLenField("random", b'\x00'*16, 16) ]

class MeshProvisioningData(Packet):
    name = "Mesh Provisioning Data"
    fields_desc = [
        ByteField("opcode", 0x07),
        StrFixedLenField("encrypted_data", b'\x00'*25, 25),
        StrFixedLenField("mic", b'\x00'*8, 8)
    ]

class MeshProvisioningComplete(Packet):
    name = "Mesh Provisioning Complete"
    fields_desc = [ ByteField("opcode", 0x08) ]

# --- Global Variables ---
master_address = 'ED:C3:BE:BA:28:30'
access_address = 0x9a328370

# These will be discovered dynamically via ATT, do not hard-code for real devices
PROV_DATA_IN_HANDLE = None
PROV_DATA_OUT_HANDLE = None
PROV_CCCD_HANDLE = None
PROV_SERVICE_START = 0x0001
PROV_SERVICE_END = 0xFFFF

prov_state = 0
slave_addr_type = 0
provisioner_key = None
prov_capabilities = None
prov_start = None
confirmation_salt = b''  # ConfirmationSalt = s1(ConfirmationInputs)
provisioning_salt = b''  # ProvisioningSalt = s1(ConfirmationSalt || RandomProvisioner || RandomDevice)
prov_invite = b''
public_key_sent = False
provisioner_rand = b''
provisionee_rand = b''
ecdh_secret = b''
session_key = b''
session_nonce = b''
device_confirmation = b''  # Store device's confirmation for verification
start_sent_time = None  # Timestamp when Start PDU was sent
pub_key_sent_time = None  # Timestamp when Public Key PDU was sent

# --- Setup ---
if len(sys.argv) < 3:
    print(Fore.RED + "Usage: python P1.py <SERIAL_PORT> <TARGET_MAC_ADDRESS>")
    sys.exit(0)

serial_port = sys.argv[1]
advertiser_address = sys.argv[2].lower()

colorama.init(autoreset=True)
print(Fore.YELLOW + 'Serial port: ' + serial_port)
print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())
print(Fore.YELLOW + "Running as: Provisioner")

driver = NRF52Dongle(serial_port, '115200', logs_pcap=True)


def send_node_reset(net_key, dev_key, device_addr, access_addr, driver, prov_data_in_handle):
    """
    Send a Node Reset message to the provisioned device.
    This is a Configuration Server message that requires:
    - Network layer encryption (with network key)
    - Transport layer encryption (with device key)
    - Access layer message construction
    - Proxy PDU wrapping
    """
    print(Fore.CYAN + 'Constructing Node Reset message...')
    
    # Derive network security material from network key
    p_value = b'\x00'
    nid, net_enc_key, net_privacy_key = k2(net_key, p_value)
    print(Fore.CYAN + f'  Derived NID: 0x{nid:02x}')
    
    # Node Reset opcode: 0x8049 (Configuration Server, Node Reset)
    node_reset_opcode = b'\x80\x49'
    
    # Access layer message: opcode (2 bytes) + no parameters
    access_payload = node_reset_opcode
    
    # Transport layer: encrypt with device key
    transport_header = b'\x00'
    transport_payload = transport_header + access_payload
    
    # Transport layer encryption with device key
    # For simplicity, use SEQ=1, SRC=0x0001 (provisioner), DST=device_addr, IVI=0
    seq = 1
    src = 0x0001  # Provisioner address (we don't have one, use placeholder)
    dst = device_addr
    iv_index = 0
    
    # Device key nonce: type(1) + padding+aszmic(1) + seq(3) + src(2) + dst(2) + iv_index(4)
    # type = 0x02 (ENC_NONCE_DEV), aszmic = 0 (unsegmented)
    transport_nonce = pack('>B', 0x02) + pack('>B', 0x00) + pack('>I', seq)[1:] + pack('>H', src) + pack('>H', dst) + pack('>I', iv_index)
    
    # Encrypt transport payload with device key
    # MIC length = 4 bytes for access messages
    cipher = AES.new(dev_key, AES.MODE_CCM, nonce=transport_nonce, mac_len=4)
    encrypted_transport, transport_mic = cipher.encrypt_and_digest(transport_payload)
    
    # Network layer: construct header and encrypt
    # Network PDU structure:
    # Byte 0: IVI(1) + NID(7)
    # Byte 1: CTL(1) + TTL(7)
    # Bytes 2-4: SEQ(24 bits, big endian)
    # Bytes 5-6: SRC(16 bits, big endian)
    # Bytes 7-8: DST(16 bits, big endian)
    # Bytes 9+: Encrypted payload (transport + network MIC)
    
    # Network header (before encryption)
    net_header = bytearray(9)
    ivi_bit = iv_index & 1  # Least significant bit of IV index
    net_header[0] = (ivi_bit << 7) | (nid & 0x7F)  # IVI + NID
    net_header[1] = (0 << 7) | (0x7F & 0x7F)  # CTL=0 (access), TTL=127
    net_header[2:5] = pack('>I', seq)[1:]  # SEQ (24 bits, big endian)
    net_header[5:7] = pack('>H', src)  # SRC (big endian)
    net_header[7:9] = pack('>H', dst)  # DST (big endian)
    
    # Network payload = encrypted transport + transport MIC
    net_payload = encrypted_transport + transport_mic
    
    # Network encryption: encrypt DST + payload with network encryption key
    # Network nonce: type(1) + ttl+ctl(1) + seq(3) + src(2) + padding(2) + iv_index(4)
    # type = 0x00 (ENC_NONCE_NET), ctl = 0, ttl = 127
    net_nonce = pack('>B', 0x00) + pack('>B', (127 << 1) | 0) + pack('>I', seq)[1:] + pack('>H', src) + b'\x00\x00' + pack('>I', iv_index)
    
    # Encrypt: DST (2 bytes) + payload, MIC length = 8 bytes
    net_enc_data = pack('>H', dst) + net_payload
    cipher = AES.new(net_enc_key, AES.MODE_CCM, nonce=net_nonce, mac_len=8)
    encrypted_net, net_mic = cipher.encrypt_and_digest(net_enc_data)
    
    # Obfuscate network header (except IVI+NID and DST)
    # PECB = AES-128(PrivacyKey, 0x0000000000 || IV_Index || PrivacyRandom[0-6])
    # PrivacyRandom = first 7 bytes of encrypted data (before MIC)
    privacy_random = encrypted_net[:7]
    pecb_data = b'\x00' * 5 + pack('>I', iv_index) + privacy_random
    pecb = AES.new(net_privacy_key, AES.MODE_ECB).encrypt(pecb_data)
    
    # Obfuscate: XOR bytes 1-6 (CTL+TTL, SEQ, SRC) with PECB[0:6]
    obfuscated_header = bytearray(net_header)
    for i in range(1, 7):
        obfuscated_header[i] ^= pecb[i-1]
    
    # Final network PDU: obfuscated header + encrypted data + MIC
    net_pdu = bytes(obfuscated_header) + encrypted_net + net_mic
    
    # Wrap in Proxy PDU
    # Proxy PDU: SAR(2) + Type(6) + Data
    # SAR = 0 (Complete), Type = 0 (Network PDU)
    # For Proxy service, we send the PDU directly (no 0x03 prefix like provisioning)
    proxy_pdu = pack('B', (0 << 6) | 0) + net_pdu  # SAR=0 (Complete), Type=0 (Network PDU)
    
    # Send via GATT to Proxy Data In characteristic
    # ATT Write Request: opcode 0x12, handle, value
    att_payload = pack('<BH', 0x12, prov_data_in_handle) + proxy_pdu
    reset_pkt = BTLE(access_addr=access_addr)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
    driver.send(reset_pkt)
    
    print(Fore.GREEN + 'Node Reset message sent via Proxy bearer!')

def discover_proxy_service(access_addr, driver):
    """
    Discover the Proxy service (0x1828) and return the Proxy Data In handle (0x2ADD).
    Returns the handle or None if not found.
    """
    print(Fore.CYAN + 'Discovering Proxy service (0x1828)...')
    
    # First, discover all primary services to find Proxy service
    read_by_group_req = pack('<BHHH', 0x10, 0x0001, 0xFFFF, 0x2800)  # Primary Service
    gatt_pkt = BTLE(access_addr=access_addr)/BTLE_DATA()/L2CAP_Hdr(cid=4)/read_by_group_req
    driver.send(gatt_pkt)
    
    # Wait for response
    timeout = time.time() + 2
    proxy_service_start = None
    proxy_service_end = None
    
    while time.time() < timeout:
        data = driver.raw_receive()
        if not data:
            time.sleep(0.01)
            continue
        
        pkt = BTLE(data)
        if ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x11:  # Read By Group Type Response
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            
            if rsp:
                entry_len = rsp[0]
                for i in range(1, len(rsp), entry_len):
                    if i + entry_len > len(rsp):
                        break
                    start_h, end_h = unpack('<HH', rsp[i:i+4])
                    if entry_len >= 6:
                        uuid16 = unpack('<H', rsp[i+4:i+6])[0]
                        if uuid16 == 0x1828:  # Proxy service
                            proxy_service_start = start_h
                            proxy_service_end = end_h
                            print(Fore.GREEN + f'Found Proxy service: start=0x{start_h:04x}, end=0x{end_h:04x}')
                            break
                if proxy_service_start:
                    break
    
    if not proxy_service_start:
        print(Fore.RED + 'Proxy service (0x1828) not found.')
        return None
    
    # Now discover Proxy Data In characteristic (0x2ADD)
    print(Fore.CYAN + 'Discovering Proxy Data In characteristic (0x2ADD)...')
    read_by_type_req = pack('<BHHH', 0x08, proxy_service_start, proxy_service_end, 0x2ADD)
    gatt_pkt = BTLE(access_addr=access_addr)/BTLE_DATA()/L2CAP_Hdr(cid=4)/read_by_type_req
    driver.send(gatt_pkt)
    
    # Wait for response
    timeout = time.time() + 2
    while time.time() < timeout:
        data = driver.raw_receive()
        if not data:
            time.sleep(0.01)
            continue
        
        pkt = BTLE(data)
        if ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x09:  # Read By Type Response
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            
            if rsp:
                entry_len = rsp[0]
                if 1 + entry_len <= len(rsp):
                    attr_handle = unpack('<H', rsp[1:3])[0]
                    print(Fore.GREEN + f'Found Proxy Data In handle: 0x{attr_handle:04x}')
                    return attr_handle
    
    print(Fore.RED + 'Proxy Data In characteristic (0x2ADD) not found.')
    return None

def handle_provisioning_failed(proxy_payload, error_code):
    """Handle provisioning failed PDU and close the connection"""
    print(Fore.RED + f'PROVISIONING FAILED! Error code: 0x{error_code:02x}')
    # Close the connection by sending LL_TERMINATE_IND
    try:
        terminate_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/CtrlPDU()/LL_TERMINATE_IND()
        driver.send(terminate_pkt)
        print(Fore.YELLOW + 'Connection closed.')
    except Exception as e:
        print(Fore.YELLOW + f'Error closing connection: {e}')
    sys.exit(1)

def check_for_failed_pdu(proxy_payload):
    """Check if the payload contains a Failed PDU and handle it"""
    if proxy_payload and len(proxy_payload) > 1 and proxy_payload[1] == 0x09: # Failed
        error_code = proxy_payload[2] if len(proxy_payload) > 2 else 0x00
        handle_provisioning_failed(proxy_payload, error_code)
        return True
    return False

# --- Main Loop ---
scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(ScanA=master_address, AdvA=advertiser_address)
driver.send(scan_req)
print(Fore.YELLOW + 'State 0: Scanning for Unprovisioned Beacon from ' + advertiser_address)

while True:
    data = driver.raw_receive()
    
    # Check timeout for Start ACK even when no packet received
    if prov_state == 3 and start_sent_time and not public_key_sent:
        if (time.time() - start_sent_time) > 0.1:  # 100ms timeout
            print(Fore.YELLOW + 'State 3: Start ACK timeout (100ms elapsed). Proceeding with Public Key...')
            provisioner_key = ECC.generate(curve='P-256')
            pub_key_bytes = provisioner_key.pointQ.x.to_bytes(32, 'big') + provisioner_key.pointQ.y.to_bytes(32, 'big')
            pub_key_pdu = MeshProvisioningPublicKey(key=pub_key_bytes)
            full_payload = b'\x03' + bytes(pub_key_pdu)
            att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
            pubkey_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
            driver.send(pubkey_pkt)
            public_key_sent = True
            pub_key_sent_time = time.time()
            prov_state = 4  # Wait for Public Key ACK
            start_sent_time = None
            print(Fore.YELLOW + f'State 4: Public Key sent ({len(pub_key_bytes)} bytes). Waiting for Public Key ACK...')
            print(Fore.CYAN + f'  Public Key X (first 8 bytes): {pub_key_bytes[:8].hex()}')
            print(Fore.CYAN + f'  Public Key Y (first 8 bytes): {pub_key_bytes[32:40].hex()}')
    
    # Check timeout for Public Key ACK even when no packet received
    if prov_state == 4 and pub_key_sent_time:
        if (time.time() - pub_key_sent_time) > 0.1:  # 100ms timeout
            print(Fore.YELLOW + 'State 4: Public Key ACK timeout (100ms elapsed). Proceeding to wait for provisionee Public Key...')
            prov_state = 5
            pub_key_sent_time = None
    
    if not data:
        time.sleep(0.01)
        continue

    pkt = BTLE(data)
    if pkt is None: continue

    if LL_CONNECTION_UPDATE_REQ in pkt:
        print(Fore.BLUE + "Peripheral requested connection parameter update. Controller will handle response.")
    
    # --- PROVISIONER STATE MACHINE ---
        if prov_state == 0 and BTLE_ADV in pkt and pkt.AdvA == advertiser_address.lower():
            print(Fore.GREEN + 'Unprovisioned Beacon Detected. Connecting...')
            slave_addr_type = pkt.TxAdd
            conn_request = BTLE()/BTLE_ADV(RxAdd=slave_addr_type,TxAdd=0)/BTLE_CONNECT_REQ(
                InitA=master_address, AdvA=advertiser_address, AA=access_address,
                crc_init=0x179a9c, win_size=2, win_offset=1, interval=150,
                latency=0, timeout=50, chM=0x1FFFFFFFFF, hop=5, SCA=0)
            driver.send(conn_request)
            prov_state = 1
            print(Fore.YELLOW + 'State 1: Connection Request Sent.')

        elif prov_state == 1 and BTLE_DATA in pkt:
            print(Fore.YELLOW + 'Connection active. Handling Link Layer negotiation...')
            # Check if device sent LL_LENGTH_REQ - respond to it
            if LL_LENGTH_REQ in pkt:
                print(Fore.GREEN + 'Device sent LL_LENGTH_REQ. Responding...')
                length_rsp = BTLE(access_addr=access_address)/BTLE_DATA()/CtrlPDU()/LL_LENGTH_RSP(
                    max_rx_bytes=251, max_rx_time=2120, max_tx_bytes=251, max_tx_time=2120)
                driver.send(length_rsp)
                prov_state = 12  # Wait for LL_LENGTH_RSP or proceed
                print(Fore.YELLOW + 'State 12: LL_LENGTH_RSP sent. Waiting...')
            else:
                # Send LL_LENGTH_REQ to negotiate larger packet sizes
                print(Fore.YELLOW + 'Sending LL_LENGTH_REQ to negotiate packet sizes...')
                length_req = BTLE(access_addr=access_address)/BTLE_DATA()/CtrlPDU()/LL_LENGTH_REQ(
                    max_rx_bytes=251, max_rx_time=2120, max_tx_bytes=251, max_tx_time=2120)
                driver.send(length_req)
                prov_state = 12  # Wait for LL_LENGTH_RSP
                print(Fore.YELLOW + 'State 12: LL_LENGTH_REQ sent. Waiting for LL_LENGTH_RSP...')

        # Handle LL_LENGTH_RSP or proceed to MTU exchange
        elif prov_state == 12:
            if LL_LENGTH_RSP in pkt:
                print(Fore.GREEN + 'LL_LENGTH_RSP received. Link Layer length negotiation complete.')
                # Now proceed to ATT MTU exchange
                mtu_req = pack('<BH', 0x02, 527) # ATT_Exchange_MTU_Req
                mtu_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/mtu_req
                driver.send(mtu_pkt)
                prov_state = 13
                print(Fore.YELLOW + 'State 13: MTU Req sent.')
            elif LL_LENGTH_REQ in pkt:
                # Device sent LL_LENGTH_REQ - respond
                print(Fore.GREEN + 'Device sent LL_LENGTH_REQ. Responding...')
                length_rsp = BTLE(access_addr=access_address)/BTLE_DATA()/CtrlPDU()/LL_LENGTH_RSP(
                    max_rx_bytes=251, max_rx_time=2120, max_tx_bytes=251, max_tx_time=2120)
                driver.send(length_rsp)
                # After responding, proceed to MTU exchange
                mtu_req = pack('<BH', 0x02, 527) # ATT_Exchange_MTU_Req
                mtu_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/mtu_req
                driver.send(mtu_pkt)
                prov_state = 13
                print(Fore.YELLOW + 'State 13: LL_LENGTH_RSP sent, MTU Req sent.')
            elif ATT_Hdr in pkt:
                # Device might have skipped LL_LENGTH and went straight to ATT
                # Proceed with MTU exchange
                mtu_req = pack('<BH', 0x02, 527) # ATT_Exchange_MTU_Req
                mtu_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/mtu_req
                driver.send(mtu_pkt)
                prov_state = 13
                print(Fore.YELLOW + 'State 13: Proceeding to MTU exchange (no LL_LENGTH negotiation).')

        # MTU response -> discover Mesh Provisioning service (UUID 0x1827)
        elif prov_state == 13 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x03: # MTU Rsp
            print(Fore.GREEN + 'MTU Exchange Complete. Discovering Mesh Provisioning service (0x1827)...')
            # ATT_Read_By_Group_Type_Req: opcode=0x10, start_handle, end_handle, group_type=0x2800 (Primary Service)
            read_by_group_req = pack('<BHHH', 0x10, 0x0001, 0xFFFF, 0x2800)
            gatt_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/read_by_group_req
            driver.send(gatt_pkt)
            prov_state = 14
            print(Fore.YELLOW + 'State 14: Primary service discovery sent.')

        # Parse Read By Group Type Response, find service with UUID 0x1827
        elif prov_state == 14 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x11:
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            if not rsp:
                prov_state = 0
                print(Fore.RED + 'Empty Read By Group Type response.')
                continue
            entry_len = rsp[0]
            print(Fore.CYAN + f'Service discovery response: entry_len={entry_len}, total_len={len(rsp)}')
            found = False
            services_found = []
            for i in range(1, len(rsp), entry_len):
                if i + entry_len > len(rsp):
                    break
                # For 16‑bit service UUID, entry_len should be 6: start, end, uuid16
                start_h, end_h = unpack('<HH', rsp[i:i+4])
                if entry_len >= 6:
                    uuid16 = unpack('<H', rsp[i+4:i+6])[0]
                    services_found.append((start_h, end_h, uuid16))
                    print(Fore.CYAN + f'  Found service: start=0x{start_h:04x}, end=0x{end_h:04x}, UUID=0x{uuid16:04x}')
                    if uuid16 == 0x1827:
                        globals()['PROV_SERVICE_START'], globals()['PROV_SERVICE_END'] = start_h, end_h
                        found = True
                        print(Fore.GREEN + f'Found Mesh Provisioning service: start=0x{start_h:04x}, end=0x{end_h:04x}')
                        break
                elif entry_len == 4:
                    # 128-bit UUID (not 16-bit)
                    print(Fore.CYAN + f'  Found service with 128-bit UUID: start=0x{start_h:04x}, end=0x{end_h:04x}')
            
            if not found:
                print(Fore.RED + 'Mesh Provisioning service (0x1827) not found.')
                if services_found:
                    print(Fore.YELLOW + 'Available services:')
                    for start, end, uuid in services_found:
                        uuid_name = {
                            0x1800: 'Generic Access',
                            0x1801: 'Generic Attribute',
                            0x1828: 'Mesh Proxy Service',
                            0x1827: 'Mesh Provisioning Service'
                        }.get(uuid, 'Unknown')
                        print(Fore.YELLOW + f'  - 0x{uuid:04x} ({uuid_name}): handles 0x{start:04x}-0x{end:04x}')
                    
                    # Check if Proxy service is present (device is already provisioned)
                    proxy_found = any(uuid == 0x1828 for _, _, uuid in services_found)
                    if proxy_found:
                        print(Fore.RED + 'Device appears to be already provisioned (Proxy service found).')
                        print(Fore.YELLOW + 'The device needs to be reset to an unprovisioned state.')
                        print(Fore.YELLOW + 'Options:')
                        print(Fore.YELLOW + '  1. Use the device\'s reset procedure (check manual)')
                        print(Fore.YELLOW + '  2. Use nrfjprog to erase flash (if nRF device)')
                        print(Fore.YELLOW + '  3. Try connecting via Proxy service to send Node Reset')
                else:
                    print(Fore.RED + 'No services found in response.')
                prov_state = 0
                continue

            # Next: discover Provisioning Data In characteristic (UUID 0x2ADB) within this service
            read_by_type_req = pack('<BHHH', 0x08, PROV_SERVICE_START, PROV_SERVICE_END, 0x2ADB)
            gatt_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/read_by_type_req
            driver.send(gatt_pkt)
            prov_state = 15
            print(Fore.YELLOW + 'State 15: Discovering Provisioning Data In characteristic (0x2ADB).')

        # Parse Read By Type Response for Provisioning Data In characteristic
        elif prov_state == 15 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x09:
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            if not rsp:
                print(Fore.RED + 'Empty Read By Type response for Provisioning Data In.')
                prov_state = 0
                continue
            entry_len = rsp[0]
            # First two bytes in each entry are the attribute handle
            attr_handle = None
            if 1 + entry_len <= len(rsp):
                attr_handle = unpack('<H', rsp[1:3])[0]
            if not attr_handle:
                print(Fore.RED + 'Failed to parse Provisioning Data In handle.')
                prov_state = 0
                continue
            globals()['PROV_DATA_IN_HANDLE'] = attr_handle
            print(Fore.GREEN + f'Provisioning Data In handle discovered: 0x{PROV_DATA_IN_HANDLE:04x}')

            # Now discover Provisioning Data Out characteristic (UUID 0x2ADC) within the same service
            read_by_type_req = pack('<BHHH', 0x08, PROV_SERVICE_START, PROV_SERVICE_END, 0x2ADC)
            gatt_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/read_by_type_req
            driver.send(gatt_pkt)
            prov_state = 16
            print(Fore.YELLOW + 'State 16: Discovering Provisioning Data Out characteristic (0x2ADC).')

        # Parse Read By Type Response for Provisioning Data Out characteristic, then find its CCCD
        elif prov_state == 16 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x09:
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            if not rsp:
                print(Fore.RED + 'Empty Read By Type response for Provisioning Data Out.')
                prov_state = 0
                continue
            entry_len = rsp[0]
            attr_handle = None
            if 1 + entry_len <= len(rsp):
                attr_handle = unpack('<H', rsp[1:3])[0]
            if not attr_handle:
                print(Fore.RED + 'Failed to parse Provisioning Data Out handle.')
                prov_state = 0
                continue
            globals()['PROV_DATA_OUT_HANDLE'] = attr_handle
            print(Fore.GREEN + f'Provisioning Data Out handle discovered: 0x{PROV_DATA_OUT_HANDLE:04x}')

            # Find CCCD (UUID 0x2902) just after the Data Out characteristic value handle
            # ATT_Find_Information_Req: opcode=0x04, start_handle, end_handle
            start_cccd = PROV_DATA_OUT_HANDLE + 1
            end_cccd = min(PROV_DATA_OUT_HANDLE + 5, PROV_SERVICE_END)
            find_info_req = pack('<BHH', 0x04, start_cccd, end_cccd)
            gatt_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/find_info_req
            driver.send(gatt_pkt)
            prov_state = 17
            print(Fore.YELLOW + 'State 17: Discovering CCCD (0x2902) for Provisioning Data Out.')

        elif prov_state == 17 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x05:
            # ATT_Find_Information_Rsp: format, then list of (handle, uuid)
            payload = pkt[ATT_Hdr].payload
            try:
                rsp = bytearray(bytes(payload))
            except TypeError:
                rsp = bytearray(payload.build())
            if not rsp:
                print(Fore.RED + 'Empty Find Information response.')
                prov_state = 0
                continue
            fmt = rsp[0]
            # format 0x01: handle + 16-bit UUID
            if fmt != 0x01:
                print(Fore.RED + 'Unexpected Find Information format. Expected 16‑bit UUIDs.')
                prov_state = 0
                continue
            found_cccd = False
            for i in range(1, len(rsp), 4):
                if i + 4 > len(rsp):
                    break
                handle, uuid16 = unpack('<HH', rsp[i:i+4])
                if uuid16 == 0x2902:
                    globals()['PROV_CCCD_HANDLE'] = handle
                    found_cccd = True
                    break

            if not found_cccd:
                print(Fore.RED + 'CCCD (0x2902) for Provisioning Data Out not found. Cannot enable notifications.')
                prov_state = 0
                continue

            print(Fore.GREEN + f'CCCD handle discovered: 0x{PROV_CCCD_HANDLE:04x}. Enabling notifications...')
            write_req = pack('<BH', 0x12, PROV_CCCD_HANDLE) + b'\x01\x00' # Write 0x0001 to CCCD
            write_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/write_req
            driver.send(write_pkt)
            prov_state = 18
            print(Fore.YELLOW + 'State 18: Enabling Mesh Notifications.')

        elif prov_state == 18 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x13: # Write Rsp
            print(Fore.GREEN + 'GATT Setup Complete. Sending Provisioning Invite.')
            prov_invite = MeshProvisioningInvite()
            full_payload = b'\x03' + bytes(prov_invite)
            att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
            invite_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
            driver.send(invite_pkt)
            prov_state = 2
            print(Fore.YELLOW + 'State 2: Invite sent. Waiting for Capabilities...')

        elif prov_state == 2 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b: # Notification
            proxy_payload = pkt[ATT_Hdr].payload.value
            if check_for_failed_pdu(proxy_payload):
                continue
            if proxy_payload and (proxy_payload[0] & 0x3F) == 3:
                prov_data = proxy_payload[1:]
                if prov_data and prov_data[0] == 0x01: # Capabilities
                    print(Fore.GREEN + 'Capabilities Received. Sending Start.')
                    prov_capabilities = prov_data
                    prov_start = MeshProvisioningStart(algorithm=0, pub_key=0, auth_method=0, auth_action=0, auth_size=0)
                    full_payload = b'\x03' + bytes(prov_start)
                    att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                    start_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                    driver.send(start_pkt)
                    start_sent_time = time.time()  # Record when Start was sent
                    prov_state = 3  # Wait for Start ACK before sending Public Key
                    print(Fore.YELLOW + 'State 3: Start sent. Waiting for Start ACK before sending Public Key...')

        # State 3: Wait for Start acknowledgment before sending Public Key
        # According to nRF5 SDK, provisioner waits in WAIT_START_ACK state
        # and only sends Public Key after receiving ACK callback
        # In GATT bearer, ACK may be implicit - wait for notification
        elif prov_state == 3 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b: # Notification
            proxy_payload = pkt[ATT_Hdr].payload.value
            if check_for_failed_pdu(proxy_payload):
                continue
            # Any notification after Start indicates device processed it (implicit ACK)
            if not public_key_sent:
                print(Fore.GREEN + 'State 3: Start ACK received (notification from device). Sending Public Key...')
                provisioner_key = ECC.generate(curve='P-256')
                # nRF5 SDK expects 64 bytes: 32 bytes X coordinate + 32 bytes Y coordinate (both big-endian)
                pub_key_bytes = provisioner_key.pointQ.x.to_bytes(32, 'big') + provisioner_key.pointQ.y.to_bytes(32, 'big')
                pub_key_pdu = MeshProvisioningPublicKey(key=pub_key_bytes)
                # Proxy PDU type (0x03) + Provisioning PDU (opcode 0x03 + 64 bytes key)
                full_payload = b'\x03' + bytes(pub_key_pdu)
                att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                pubkey_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                driver.send(pubkey_pkt)
                public_key_sent = True
                pub_key_sent_time = time.time()  # Record when Public Key was sent
                prov_state = 4  # Wait for Public Key ACK before expecting provisionee's Public Key
                start_sent_time = None  # Reset Start timestamp
                print(Fore.YELLOW + f'State 4: Public Key sent ({len(pub_key_bytes)} bytes). Waiting for Public Key ACK...')
                print(Fore.CYAN + f'  Public Key X (first 8 bytes): {pub_key_bytes[:8].hex()}')
                print(Fore.CYAN + f'  Public Key Y (first 8 bytes): {pub_key_bytes[32:40].hex()}')

        # State 4: Wait for Public Key acknowledgment
        # According to nRF5 SDK, provisioner waits in WAIT_PUB_KEY_ACK state
        # After ACK, it transitions to WAIT_PUB_KEY to wait for provisionee's Public Key
        # In GATT, the provisionee's Public Key notification serves as the ACK
        elif prov_state == 4 and ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b: # Notification
            proxy_payload = pkt[ATT_Hdr].payload.value
            if check_for_failed_pdu(proxy_payload):
                continue
            if proxy_payload and len(proxy_payload) > 1:
                # Check if this is the provisionee's Public Key (which serves as the ACK)
                if proxy_payload[1] == 0x03: # Public Key PDU
                    print(Fore.GREEN + 'State 4: Received provisionee Public Key (serves as ACK). Processing...')
                    # Process it directly (same as state 5)
                    prov_data = proxy_payload[1:]
                    device_pub_key_x_bytes = bytes(prov_data[1:33])
                    device_pub_key_y_bytes = bytes(prov_data[33:65])
                    device_pub_key_x = int.from_bytes(device_pub_key_x_bytes, 'big')
                    device_pub_key_y = int.from_bytes(device_pub_key_y_bytes, 'big')
                    device_key_point = ECC.EccPoint(device_pub_key_x, device_pub_key_y, curve='P-256')
                    shared_secret = provisioner_key.d * device_key_point
                    ecdh_secret = shared_secret.x.to_bytes(32, 'big')
                    
                    # Manually construct the ConfirmationInputs string
                    # PDU values must EXCLUDE the PDU type byte (first byte)
                    invite_pdu = bytes(MeshProvisioningInvite())
                    invite_value = invite_pdu[1:] if len(invite_pdu) > 1 else invite_pdu  # Skip PDU type (0x00)
                    caps_value = prov_capabilities[1:] if prov_capabilities and len(prov_capabilities) > 1 else prov_capabilities  # Skip PDU type (0x01)
                    start_pdu = bytes(prov_start)
                    start_value = start_pdu[1:] if len(start_pdu) > 1 else start_pdu  # Skip PDU type (0x02)
                    
                    conf_inputs = invite_value + caps_value + start_value
                    conf_inputs += bytes(provisioner_key.pointQ.x.to_bytes(32, 'big'))
                    conf_inputs += bytes(provisioner_key.pointQ.y.to_bytes(32, 'big'))
                    conf_inputs += device_pub_key_x_bytes
                    conf_inputs += device_pub_key_y_bytes

                    # Now calculate the ConfirmationSalt from these inputs
                    confirmation_salt = s1(conf_inputs)
                    
                    provisioner_rand = os.urandom(16)
                    # For No OOB, auth_value is 16 bytes of zeros
                    auth_value = b'\x00' * 16
                    # Confirmation = AES-CMAC(ConfirmationKey, LocalRandom || AuthValue)
                    random_and_auth = provisioner_rand + auth_value
                    # ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
                    confirmation_key = k1(ecdh_secret, confirmation_salt, b'prck')
                    provisioner_conf = CMAC.new(confirmation_key, ciphermod=AES).update(random_and_auth).digest()
                    
                    conf_pdu = MeshProvisioningConfirmation(confirmation=provisioner_conf)
                    full_payload = b'\x03' + bytes(conf_pdu)
                    att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                    conf_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                    driver.send(conf_pkt)
                    prov_state = 6
                    pub_key_sent_time = None
                    print(Fore.YELLOW + 'State 6: Confirmation sent. Waiting for device Confirmation...')
                else:
                    # Other notification - treat as implicit ACK, wait for Public Key
                    print(Fore.GREEN + 'State 4: Public Key ACK received (notification). Now waiting for provisionee Public Key...')
                    prov_state = 5
                    pub_key_sent_time = None

        elif prov_state == 5 and (ATT_Handle_Value_Notification in pkt or (ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b)):
            # Handle both ATT_Handle_Value_Notification and raw ATT_Hdr with notification opcode
            if ATT_Handle_Value_Notification in pkt:
                proxy_payload = pkt[ATT_Handle_Value_Notification].value
            else:
                proxy_payload = pkt[ATT_Hdr].payload.value
            
            if check_for_failed_pdu(proxy_payload):
                continue
            
            if proxy_payload and proxy_payload[1] == 0x03: # Public Key
                print(Fore.GREEN + 'Device Public Key Received.')
                prov_data = proxy_payload[1:]
                device_pub_key_x_bytes = bytes(prov_data[1:33])
                device_pub_key_y_bytes = bytes(prov_data[33:65])
                device_pub_key_x = int.from_bytes(device_pub_key_x_bytes, 'big')
                device_pub_key_y = int.from_bytes(device_pub_key_y_bytes, 'big')
                device_key_point = ECC.EccPoint(device_pub_key_x, device_pub_key_y, curve='P-256')
                shared_secret = provisioner_key.d * device_key_point
                ecdh_secret = shared_secret.x.to_bytes(32, 'big')
                
                # Manually construct the ConfirmationInputs string
                # PDU values must EXCLUDE the PDU type byte (first byte)
                invite_pdu = bytes(MeshProvisioningInvite())
                invite_value = invite_pdu[1:] if len(invite_pdu) > 1 else invite_pdu  # Skip PDU type (0x00)
                caps_value = prov_capabilities[1:] if prov_capabilities and len(prov_capabilities) > 1 else prov_capabilities  # Skip PDU type (0x01)
                start_pdu = bytes(prov_start)
                start_value = start_pdu[1:] if len(start_pdu) > 1 else start_pdu  # Skip PDU type (0x02)
                
                conf_inputs = invite_value + caps_value + start_value
                conf_inputs += bytes(provisioner_key.pointQ.x.to_bytes(32, 'big'))
                conf_inputs += bytes(provisioner_key.pointQ.y.to_bytes(32, 'big'))
                conf_inputs += device_pub_key_x_bytes
                conf_inputs += device_pub_key_y_bytes

                # Now calculate the ConfirmationSalt from these inputs
                confirmation_salt = s1(conf_inputs)
                
                provisioner_rand = os.urandom(16)
                # For No OOB, auth_value is 16 bytes of zeros
                auth_value = b'\x00' * 16
                # Confirmation = AES-CMAC(ConfirmationKey, LocalRandom || AuthValue)
                random_and_auth = provisioner_rand + auth_value
                # ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
                confirmation_key = k1(ecdh_secret, confirmation_salt, b'prck')
                provisioner_conf = CMAC.new(confirmation_key, ciphermod=AES).update(random_and_auth).digest()
                
                conf_pdu = MeshProvisioningConfirmation(confirmation=provisioner_conf)
                full_payload = b'\x03' + bytes(conf_pdu)
                att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                conf_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                driver.send(conf_pkt)
                prov_state = 6
                print(Fore.YELLOW + 'State 6: Confirmation sent. Waiting for device Confirmation...')

        elif prov_state == 6 and (ATT_Handle_Value_Notification in pkt or (ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b)):
            # Handle both ATT_Handle_Value_Notification and raw ATT_Hdr with notification opcode
            if ATT_Handle_Value_Notification in pkt:
                proxy_payload = pkt[ATT_Handle_Value_Notification].value
            else:
                proxy_payload = pkt[ATT_Hdr].payload.value
            
            if check_for_failed_pdu(proxy_payload):
                continue
            
            if proxy_payload and proxy_payload[1] == 0x05: # Confirmation
                print(Fore.GREEN + 'Device Confirmation Received. Sending Random...')
                device_confirmation = proxy_payload[2:18]  # Store for verification
                rand_pdu = MeshProvisioningRandom(random=provisioner_rand)
                full_payload = b'\x03' + bytes(rand_pdu)
                att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                rand_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                driver.send(rand_pkt)
                prov_state = 7
                print(Fore.YELLOW + 'State 7: Random sent. Waiting for device Random...')

        elif prov_state == 7 and (ATT_Handle_Value_Notification in pkt or (ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b)):
            # Handle both ATT_Handle_Value_Notification and raw ATT_Hdr with notification opcode
            if ATT_Handle_Value_Notification in pkt:
                proxy_payload = pkt[ATT_Handle_Value_Notification].value
            else:
                proxy_payload = pkt[ATT_Hdr].payload.value
            
            if check_for_failed_pdu(proxy_payload):
                continue
            
            if proxy_payload and proxy_payload[1] == 0x06: # Random
                print(Fore.GREEN + 'Device Random Received. Verifying confirmation and sending Provisioning Data...')
                provisionee_rand = proxy_payload[2:18]
                
                # Verify the device's confirmation
                # ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
                confirmation_key = k1(ecdh_secret, confirmation_salt, b'prck')
                # Device's confirmation should be: AES-CMAC(ConfirmationKey, DeviceRandom || AuthValue)
                auth_value = b'\x00' * 16  # No OOB
                random_and_auth = provisionee_rand + auth_value
                expected_device_conf = CMAC.new(confirmation_key, ciphermod=AES).update(random_and_auth).digest()
                
                if device_confirmation and device_confirmation == expected_device_conf:
                    print(Fore.GREEN + 'Device confirmation verified successfully!')
                else:
                    print(Fore.YELLOW + 'Warning: Device confirmation verification failed, but proceeding...')
                
                # Now calculate ProvisioningSalt = s1(ConfirmationSalt || RandomProvisioner || RandomDevice)
                provisioning_salt_data = confirmation_salt + provisioner_rand + provisionee_rand
                provisioning_salt = s1(provisioning_salt_data)
                
                # Now calculate session keys using ProvisioningSalt
                session_key = k1(ecdh_secret, provisioning_salt, b'prsk')
                session_nonce = k1(ecdh_secret, provisioning_salt, b'prsn')[3:]
                
                net_key = os.urandom(16)
                key_index = 0
                flags = 0  # key_refresh=0, iv_update=0, _rfu=0
                iv_index = 0
                unicast_addr = 0x000b
                
                # Build data block: netkey[16] + netkey_index[2] + flags[1] + iv_index[4] + address[2]
                # Total: 16 + 2 + 1 + 4 + 2 = 25 bytes
                prov_data_payload = net_key + pack('>H', key_index) + pack('B', flags) + pack('>I', iv_index) + pack('>H', unicast_addr)
                
                if len(prov_data_payload) != 25:
                    print(Fore.RED + f'ERROR: Data block size is {len(prov_data_payload)}, expected 25!')
                    sys.exit(1)
                
                # DeviceKey = k1(ECDHSecret, ProvisioningSalt, "prdk")
                dev_key = k1(ecdh_secret, provisioning_salt, b'prdk')
                
                # AES-CCM with 8-byte MIC (PROV_PDU_DATA_MIC_LENGTH)
                # Nonce length is 13 bytes (we already took [3:] from the 16-byte key)
                if len(session_nonce) != 13:
                    print(Fore.RED + f'ERROR: Session nonce size is {len(session_nonce)}, expected 13!')
                    sys.exit(1)
                
                cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_nonce, mac_len=8)
                encrypted_data, mic = cipher.encrypt_and_digest(prov_data_payload)
                
                if len(encrypted_data) != 25:
                    print(Fore.RED + f'ERROR: Encrypted data size is {len(encrypted_data)}, expected 25!')
                    sys.exit(1)
                
                if len(mic) != 8:
                    print(Fore.RED + f'ERROR: MIC size is {len(mic)}, expected 8!')
                    sys.exit(1)
                
                print(Fore.CYAN + f'  Provisioning Data: {len(prov_data_payload)} bytes plaintext, {len(encrypted_data)} bytes encrypted, {len(mic)} bytes MIC')
                
                data_pdu = MeshProvisioningData(encrypted_data=encrypted_data, mic=mic)
                full_payload = b'\x03' + bytes(data_pdu)
                att_payload = pack('<BH', 0x52, PROV_DATA_IN_HANDLE) + full_payload
                data_pkt = BTLE(access_addr=access_address)/BTLE_DATA()/L2CAP_Hdr(cid=4)/att_payload
                driver.send(data_pkt)
                prov_state = 8
                print(Fore.YELLOW + 'State 8: Provisioning Data sent. Waiting for Complete...')

        elif prov_state == 8 and (ATT_Handle_Value_Notification in pkt or (ATT_Hdr in pkt and pkt[ATT_Hdr].opcode == 0x1b)):
            # Handle both ATT_Handle_Value_Notification and raw ATT_Hdr with notification opcode
            if ATT_Handle_Value_Notification in pkt:
                proxy_payload = pkt[ATT_Handle_Value_Notification].value
            else:
                proxy_payload = pkt[ATT_Hdr].payload.value
            
            if proxy_payload and proxy_payload[1] == 0x08: # Complete
                print(Fore.GREEN + 'PROVISIONING COMPLETE!')
                print(Fore.CYAN + f'  Network Key: {net_key.hex()}')
                print(Fore.CYAN + f'  Device Key: {dev_key.hex()}')
                print(Fore.CYAN + f'  Unicast Address: 0x{unicast_addr:04x}')
                
                # Ask user if they want to send Node Reset
                print(Fore.YELLOW + '\n' + '='*60)
                print(Fore.YELLOW + 'Device has been provisioned successfully!')
                print(Fore.YELLOW + '')
                print(Fore.CYAN + 'Would you like to send a node reset message to reset the device?')
                print(Fore.CYAN + 'This will clear all mesh state and make it unprovisioned again.')
                print(Fore.YELLOW + '')
                user_input = input(Fore.CYAN + 'Send node reset? (y/n): ').strip().lower()
                
                if user_input == 'y' or user_input == 'yes':
                    print(Fore.YELLOW + 'Discovering proxy service to send node reset...')
                    # After provisioning, device switches to Proxy service (0x1828)
                    # We need to discover Proxy Data In characteristic (0x2ADD)
                    proxy_data_in_handle = discover_proxy_service(access_address, driver)
                    if proxy_data_in_handle:
                        print(Fore.YELLOW + f'Sending Node Reset message via Proxy service (handle 0x{proxy_data_in_handle:04x})...')
                        try:
                            send_node_reset(net_key, dev_key, unicast_addr, access_address, driver, proxy_data_in_handle)
                            print(Fore.GREEN + 'Node reset message sent!')
                            print(Fore.YELLOW + 'The device should reset and become unprovisioned.')
                            print(Fore.YELLOW + 'You may need to wait a few seconds for the reset to complete.')
                        except Exception as e:
                            print(Fore.RED + f'Error sending Node Reset: {e}')
                            import traceback
                            traceback.print_exc()
                            print(Fore.YELLOW + 'You can still reset manually using:')
                            print(Fore.YELLOW + '  - Button 4 on the device')
                            print(Fore.YELLOW + '  - RTT input "4"')
                            print(Fore.YELLOW + '  - nrfjprog --eraseall -f nrf52')
                    else:
                        print(Fore.RED + 'Failed to discover proxy service. Cannot send node reset.')
                        print(Fore.YELLOW + 'The device may have already disconnected or proxy service is not available.')
                else:
                    print(Fore.YELLOW + 'Skipping node reset.')
                    print(Fore.YELLOW + 'To reset manually:')
                    print(Fore.YELLOW + '  - Press button 4 on the device')
                    print(Fore.YELLOW + '  - Send "4" via RTT')
                    print(Fore.YELLOW + '  - Use: nrfjprog --eraseall -f nrf52')
                
                print(Fore.YELLOW + '='*60)
                
                print(Fore.CYAN + '\nExiting in 3 seconds...')
                time.sleep(3)
                sys.exit(0)
            elif proxy_payload and proxy_payload[1] == 0x09: # Failed
                error_code = proxy_payload[2] if len(proxy_payload) > 2 else 0x00
                handle_provisioning_failed(proxy_payload, error_code)