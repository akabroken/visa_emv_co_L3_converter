from os import pipe
import re
from lxml import etree as ET
from datetime import datetime, timezone


def parse_inovant_log(log_data):
    messages = []
    raw_messages = re.split(r'(?=ISO\^)', log_data.strip())
    raw_messages = [msg.strip() for msg in raw_messages if msg.strip()]

    for msg_block in raw_messages:
        # Extract MTI
        mti_match = re.search(r'\b(01[01]0)\b', msg_block)
        if not mti_match:
            mti_match = re.search(r'sID:MTI.*?sDATA:(01[01]0)', msg_block)
            if not mti_match:
                continue
        mti = mti_match.group(1)
        
        class_type = "Request" if mti == "0100" else "Response"
        source, destination = ("N/A", "TestIssuer|Network") if class_type == "Request" else ("TestIssuer|Network", "N/A")

        # New improved field pattern
        field_pattern = r'~sID:([^ ~]+)\s+sNAME:([^~]+?)\s+sDATA:([^~]*?)(?:\s+sACDATA:([^~]*?))?(?=\s+~|$)'
        all_fields = re.findall(field_pattern, msg_block, re.DOTALL)

        # Process fields
        fields = []
        for fid, fname, fdata, facdata in all_fields:
            field = {
                'id': fid.strip(),
                'name': fname.strip(),
                'value': fdata.strip() if fdata else '',
                'acdata': facdata.strip() if facdata else None
            }
            fields.append(field)

        message = {
            'mti': mti,
            'class': class_type,
            'source': source,
            'destination': destination,
            'incoming_fields': fields if class_type == "Request" else [],
            'outgoing_fields': [] if class_type == "Request" else fields
        }
        messages.append(message)

    return messages

def guess_field_type(fid):
    field_types = {
        "F2": "N..19",
        "F3": "n6",
        "F4": "n12",
        "F7": "MMDDhhmmss",
        "F11": "n6",
        "F19": "n3",
        "F23": "n3",
        "F25": "n2",
        "F32": "ANS6",
        "F35": "ANS37",
        "F37": "ANS12",
        "F38": "ANS6",
        "F39": "an2",
        "F41": "ANS8",
        "F42": "ANS15",
        "F49": "n3",
        "F55": "B..255",
        "F62": "B..999",
        "F63": "AN..50"
    }
    return field_types.get(fid, "unknown")


def generate_emvco_l3_xml(messages):
    root = ET.Element("EMVCoL3OnlineMessageFormat")

    # LogDetails
    log_details = ET.SubElement(root, "LogDetails")
    ET.SubElement(log_details, "Date-Time").text = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = ET.SubElement(log_details, "LoggingTool")
    ET.SubElement(tool, "ProductName").text = "Inovant VTS Simulator"
    ET.SubElement(tool, "ProductVersion").text = "1.0.0"
    ET.SubElement(log_details, "SchemaSelectionIndex").text = "1.1"
    ET.SubElement(log_details, "Reference").text = "EMVCo L3 Online Message Format"
    ET.SubElement(log_details, "L3OMLVersion").text = "1.1"

    # ConnectionList
    conn_list = ET.SubElement(root, "ConnectionList")
    conn = ET.SubElement(conn_list, "Connection", ID="TestIssuer|Network")
    proto = ET.SubElement(conn, "Protocol")
    ET.SubElement(proto, "FriendlyName").text = "VISA VSDC"
    ET.SubElement(proto, "SymbolicName").text = "VISAVSDC"
    ET.SubElement(proto, "VersionInfo").text = "1.0.0"
    tcpip = ET.SubElement(conn, "TCPIPParameters")
    ET.SubElement(tcpip, "Address").text = "."
    ET.SubElement(tcpip, "Port").text = "1234"
    ET.SubElement(tcpip, "Client").text = "false"
    ET.SubElement(tcpip, "Format").text = "ASCII"

    # OnlineMessageList
    online_msg_list = ET.SubElement(root, "OnlineMessageList")

    for msg in messages:
        mti = msg['mti']
        class_type = msg['class']

        if class_type == "Request":
            online_msg = ET.SubElement(online_msg_list, "OnlineMessage",
                                       Class="Request",
                                       Source=msg['source'],
                                       Destination=msg['destination'])
            ET.SubElement(online_msg, "RawData").text = "HEXDATAPLACEHOLDER"
            msg_info = ET.SubElement(online_msg, "MessageInfo")
            ET.SubElement(msg_info, "PINValidated").text = "N/A"
            ET.SubElement(msg_info, "ARQCValidated").text = "true"
            ET.SubElement(msg_info, "MACValidated").text = "N/A"
            ET.SubElement(msg_info, "CVC3Track1Validated").text = "N/A"
            ET.SubElement(msg_info, "CVC3Track2Validated").text = "N/A"
            ET.SubElement(msg_info, "ToolComment").text = "Request Authorization"

            message_elem = ET.SubElement(online_msg, "Message", Class="Request")
            ET.SubElement(message_elem, "MessageName").text = mti
            ET.SubElement(message_elem, "MTI").text = mti

            field_list = ET.SubElement(message_elem, "FieldList")
            for field in msg['incoming_fields']:
                fid = field['id']
                fname = field['name']
                fvalue = field['value']
                facdata = field['acdata']
                field_elem = ET.SubElement(field_list, "Field", ID=f"NET.{mti}.DE.{fid}")
                ET.SubElement(field_elem, "FriendlyName").text = fname
                ET.SubElement(field_elem, "FieldType").text = guess_field_type(fid)
                ET.SubElement(field_elem, "FieldBinary").text = bytes(fvalue, 'utf-8').hex().upper()
                ET.SubElement(field_elem, "FieldViewable").text = facdata

        elif class_type == "Response":
            online_msg = ET.SubElement(online_msg_list, "OnlineMessage",
                                       Class="Response",
                                       Source=msg['source'],
                                       Destination=msg['destination'])
            ET.SubElement(online_msg, "RawData").text = "HEXDATAPLACEHOLDER"
            msg_info = ET.SubElement(online_msg, "MessageInfo")
            ET.SubElement(msg_info, "PINValidated").text = "N/A"
            ET.SubElement(msg_info, "ARQCValidated").text = "N/A"
            ET.SubElement(msg_info, "MACValidated").text = "N/A"
            ET.SubElement(msg_info, "CVC3Track1Validated").text = "N/A"
            ET.SubElement(msg_info, "CVC3Track2Validated").text = "N/A"
            ET.SubElement(msg_info, "ToolComment").text = "Response Authorization"

            message_elem = ET.SubElement(online_msg, "Message", Class="Response")
            ET.SubElement(message_elem, "MessageName").text = mti
            ET.SubElement(message_elem, "MTI").text = mti

            field_list = ET.SubElement(message_elem, "FieldList")
            for field in msg['outgoing_fields']:
                fid = field['id']
                fname = field['name']
                fvalue = field['value']
                facdata = field['acdata']
                field_elem = ET.SubElement(field_list, "Field", ID=f"NET.{mti}.DE.{fid}")
                ET.SubElement(field_elem, "FriendlyName").text = fname
                ET.SubElement(field_elem, "FieldType").text = guess_field_type(fid)
                ET.SubElement(field_elem, "FieldBinary").text = bytes(fvalue, 'utf-8').hex().upper()
                ET.SubElement(field_elem, "FieldViewable").text = fvalue
                print(f"Added field: ID={fid}, Name={fname}, Value={fvalue}, ACData={facdata}")

    # Optional signature stub
    #sig = ET.SubElement(root, "Signature", xmlns="http://www.w3.org/2000/09/xmldsig#")
    #signed_info = ET.SubElement(sig, "SignedInfo")
    #ET.SubElement(signed_info, "CanonicalizationMethod",
    #              Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    #ET.SubElement(signed_info, "SignatureMethod",
    #              Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    #ref = ET.SubElement(signed_info, "Reference", URI="")
    #transforms = ET.SubElement(ref, "Transforms")
    #ET.SubElement(transforms, "Transform",
    #              Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    #ET.SubElement(ref, "DigestMethod", Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
    #ET.SubElement(ref, "DigestValue").text = "DummyDigest=="

    return root


if __name__ == "__main__":
    log_string = '''ISO^INFO^^^20250607134420^0110 ISO Message, OUTGOING (VIS). Sending out.~sID:H01 sNAME:Header Length sDATA:16~sID:H02 sNAME:Header Flag and Format sDATA:01~sID:H03 sNAME:Text Format sDATA:02~sID:H04 sNAME:Total Message Length sDATA:0092~sID:H05 sNAME:Destination Station Id sDATA:192425~sID:H06 sNAME:Source Station Id sDATA:000000~sID:H07 sNAME:Round Trip Control Information sDATA:00~sID:H08 sNAME:BASE I Flags sDATA:0000~sID:H09 sNAME:Message Status Flags sDATA:000000~sID:H10 sNAME:Batch Number sDATA:00~sID:H11 sNAME:Reserved sDATA:000000~sID:H12 sNAME:User Information sDATA:00~sID:MTI sNAME:Message Type Indicator sDATA:0110~sID:BMP sNAME:BitMap sDATA:722022810EC08206~sID:F2 sNAME:Primary Account Number sDATA:4761730000000029~sID:F3 sNAME:Processing Code sDATA:001000~sID:F4 sNAME:Amount Transaction sDATA:000000660000~sID:F7 sNAME:Transmission Date and Time sDATA:0607104421~sID:F11 sNAME:System Trace Audit Number sDATA:154125~sID:F15 sNAME:Date, Settlement sDATA:~sID:F19 sNAME:Acquiring Country Code sDATA:404~sID:F23 sNAME:Card Sequence Number sDATA:001~sID:F25 sNAME:POS Condition Code sDATA:00~sID:F32 sNAME:Acquiring ID sDATA:458784~sID:F37 sNAME:Retrieval Reference Number sDATA:515883020143~sID:F38 sNAME:Authorization Identification Response sDATA:009671~sID:F39 sNAME:Response Code sDATA:00~sID:F41 sNAME:Card Acceptor Terminal Id sDATA:00087130~sID:F42 sNAME:Card Acceptor Id Code sDATA:8637241449     ~sID:F49 sNAME:Currency Code, Transaction sDATA:404~sID:F55 sNAME:Chip Data sDATA:01000F9F100706011203A000009F36020001~sID:F55.1 sNAME:Dataset ID sDATA:01~sID:F55.2 sNAME:Dataset Length sDATA:000F~sID:F55.7 sNAME:Tag 9F10 - Issuer Application Data (IAD) sDATA:9F100706011203A00000~sID:F55.7.1 sNAME:TLV Tag ID sDATA:9F10~sID:F55.7.2 sNAME:TLV Length sDATA:07~sID:F55.7.3 sNAME:TLV Length 1 sDATA:06~sID:F55.7.4 sNAME:TLV Value 1 (VISA DISCRE DATA) sDATA:011203A00000~sID:F55.9 sNAME:Tag 9F36 - Application Transaction Counter sDATA:9F36020001~sID:F55.9.1 sNAME:TLV Tag ID sDATA:9F36~sID:F55.9.2 sNAME:TLV Length sDATA:02~sID:F55.9.3 sNAME:TLV Value 1 (APPL TXN CNTR) sDATA:0001~sID:F62 sNAME:Custom Payment Service Fields sDATA:0000000000000000~sID:F62 BMP sNAME:Bitmap sDATA:0000000000000000~sID:F62.2 sNAME:Transaction Identifier sDATA:~sID:F63 sNAME:SMS Private-Use Fields sDATA:8000000000~sID:F63 BMP sNAME:Bitmap sDATA:800000~sID:F63.1 sNAME:Network Identification Code sDATA:0000^Case 5.1 Authorization - Unspecified Account^VSDC POS Orig Auth 0110 Out Rsp
ISO^WARNING^^^20250607134420^0100 ISO Message, INCOMING (VIS). Match found~sID:H01 sNAME:Header Length sDATA:ValidValue sACDATA:16~sID:H02 sNAME:Header Flag and Format sDATA:01 sACDATA:01~sID:H03 sNAME:Text Format sDATA:02 sACDATA:02~sID:H04 sNAME:Total Message Length sDATA:ValidValue sACDATA:0137~sID:H05 sNAME:Destination Station Id sDATA:ValidValue sACDATA:000000~sID:H06 sNAME:Source Station Id sDATA:ValidValue sACDATA:192425~sID:H07 sNAME:Round Trip Control Information sDATA:ValidValue sACDATA:00~sID:H08 sNAME:BASE I Flags sDATA:ValidValue sACDATA:0000~sID:H09 sNAME:Message Status Flags sDATA:ValidValue sACDATA:000000~sID:H10 sNAME:Batch Number sDATA:ValidValue sACDATA:00~sID:H11 sNAME:Reserved sDATA:ValidValue sACDATA:000000~sID:H12 sNAME:User Information sDATA:ValidValue sACDATA:00~sID:MTI sNAME:Message Type Indicator sDATA:0100 sACDATA:0100~sID:BMP sNAME:BitMap sDATA:ValidValue sACDATA:723C668128E08216~sID:F2 sNAME:Primary Account Number sDATA:ValidValue sACDATA:4761730000000029~sID:F3 sNAME:Processing Code sDATA:SubfieldLevel sACDATA:000000~sID:F3.1 sNAME:Transaction Type sDATA:00 sACDATA:00~sID:F3.2 sNAME:Account Type From sDATA:ValidValue sACDATA:00~sID:F3.3 sNAME:Account Type To sDATA:00 sACDATA:00~sID:F4 sNAME:Amount Transaction sDATA:ValidValue sACDATA:000000660000~sID:F7 sNAME:Transmission Date and Time sDATA:ValidValue sACDATA:0607104421~sID:F11 sNAME:System Trace Audit Number sDATA:ValidValue sACDATA:154125~sID:F12 sNAME:Time, Local Transmission sDATA:ValidValue sACDATA:064421~sID:F13 sNAME:Date, Local Transmission sDATA:ValidValue sACDATA:0607~sID:F14 sNAME:Expiration Date sDATA:ValidValue sACDATA:3112~sID:F15 sNAME:Date, Settlement sDATA:ValidValue sACDATA:{Expected, But Not Received}~sID:F18 sNAME:Merchant's Type sDATA:4511 sACDATA:5411~sID:F19 sNAME:Acquiring Country Code sDATA:ValidValue sACDATA:404~sID:F22 sNAME:POS Entry Mode Code sDATA:SubfieldLevel sACDATA:0510~sID:F22.1 sNAME:PAN/Date Entry Mode sDATA:05 sACDATA:05~sID:F22.2 sNAME:PIN Entry Capability sDATA:ValidValue sACDATA:1~sID:F22.3 sNAME:Filler sDATA:ValidValue sACDATA:0~sID:F23 sNAME:Card Sequence Number sDATA:ValidValue sACDATA:001~sID:F25 sNAME:POS Condition Code sDATA:ValidValue sACDATA:00~sID:F32 sNAME:Acquiring ID sDATA:ValidValue sACDATA:458784~sID:F35 sNAME:Track 2 Data sDATA:SubfieldLevel sACDATA:4761730000000029D311220115434134~sID:F35.01 sNAME:PAN sDATA:ValidValue sACDATA:4761730000000029~sID:F35.02 sNAME:Separator sDATA:D sACDATA:D~sID:F35.03 sNAME:Expiration Date sDATA:ValidValue sACDATA:3112~sID:F35.04 sNAME:Service Code sDATA:ValidValue sACDATA:201~sID:F35.05 sNAME:PVV sDATA:ValidValue sACDATA:15434~sID:F35.06 sNAME:Discretionary Data sDATA:ValidValue sACDATA:134~sID:F37 sNAME:Retrieval Reference Number sDATA:ValidValue sACDATA:515883020143~sID:F41 sNAME:Card Acceptor Terminal Id sDATA:ValidValue sACDATA:00087130~sID:F42 sNAME:Card Acceptor Id Code sDATA:ValidValue sACDATA:8637241449     ~sID:F43 sNAME:Card Acceptor Name/Location sDATA:ValidValue sACDATA:TUSKYS KILIFI            KILIFI       KE~sID:F44 sNAME:Additional Response Data sDATA:ValidValue sACDATA:{Expected, But Not Received}~sID:F49 sNAME:Currency Code, Transaction sDATA:ValidValue sACDATA:404~sID:F55 sNAME:Chip Data sDATA:SubfieldLevel sACDATA:01006C9F3303E068E8950580800080009F3704092013869F101706011203A000000F00564953414C3354455354434153459F2608EB3C3E0392504A519F36020001820218009C01009F1A0204049A032506079F02060000006600005F2A0204049F03060000000000009F34031E0300~sID:F55.1 sNAME:Dataset ID sDATA:ValidValue sACDATA:01~sID:F55.2 sNAME:Dataset Length sDATA:ValidValue sACDATA:006C~sID:F55.3 sNAME:Tag 9F33 - Terminal Capability Profile sDATA:ValidValue sACDATA:9F3303E068E8~sID:F55.4 sNAME:Tag 95 - Terminal Verification Results (TVR) sDATA:ValidValue sACDATA:95058080008000~sID:F55.5 sNAME:Tag 9F37 - Unpredictable Number sDATA:ValidValue sACDATA:9F370409201386~sID:F55.7 sNAME:Tag 9F10 - Issuer Application Data (IAD) sDATA:SubfieldLevel sACDATA:9F101706011203A000000F00564953414C335445535443415345~sID:F55.7.1 sNAME:TLV Tag ID sDATA:9F10 sACDATA:9F10~sID:F55.7.2 sNAME:TLV Length sDATA:ValidValue sACDATA:17~sID:F55.7.3 sNAME:TLV Length 1 sDATA:ValidValue sACDATA:06~sID:F55.7.4 sNAME:TLV Value 1 (VISA DISCRE DATA) sDATA:ValidValue sACDATA:011203A00000~sID:F55.7.5 sNAME:TLV Length 2 sDATA:{Received, But Not Expected} sACDATA:0F~sID:F55.7.6 sNAME:TLV Value 2 (ISS DISCRE DATA) sDATA:{Received, But Not Expected} sACDATA:00564953414C335445535443415345~sID:F55.8 sNAME:Tag 9F26 - Cryptogram sDATA:ValidValue sACDATA:9F2608EB3C3E0392504A51~sID:F55.9 sNAME:Tag 9F36 - Application Transaction Counter sDATA:ValidValue sACDATA:9F36020001~sID:F55.10 sNAME:Tag 82 - Application Interchange Profile sDATA:ValidValue sACDATA:82021800~sID:F55.11 sNAME:Tag 9C - Cryptogram Transaction Type sDATA:ValidValue sACDATA:9C0100~sID:F55.12 sNAME:Tag 9F1A - Terminal Country Code sDATA:ValidValue sACDATA:9F1A020404~sID:F55.13 sNAME:Tag 9A - Terminal Transaction Date (YYMMDD) sDATA:ValidValue sACDATA:9A03250607~sID:F55.14 sNAME:Tag 9F02 - Cryptogram Amount sDATA:ValidValue sACDATA:9F0206000000660000~sID:F55.15 sNAME:Tag 5F2A - Cryptogram Currency Code sDATA:ValidValue sACDATA:5F2A020404~sID:F55.16 sNAME:Tag 9F03 - Cryptogram Cashback Amount sDATA:ValidValue sACDATA:9F0306000000000000~sID:F55.23 sNAME:Tag 84 - Application Identifier (AID) sDATA:ValidValue sACDATA:{Expected, But Not Received}~sID:F55.25 sNAME:Tag 9F34 - CVM Results sDATA:{Received, But Not Expected} sACDATA:9F34031E0300~sID:F60 sNAME:Additional POS Information sDATA:ValidValue sACDATA:050000100001~sID:F62 sNAME:Custom Payment Service Fields sDATA:SubfieldLevel sACDATA:00001000000000005901110200~sID:F62 BMP sNAME:Bitmap sDATA:ValidValue sACDATA:0000100000000000~sID:F62.2 sNAME:Transaction Identifier sDATA:ValidValue sACDATA:{Expected, But Not Received}~sID:F62.20 sNAME:Merchant Verification Value sDATA:{Received, But Not Expected} sACDATA:5901110200~sID:F62.23 sNAME:Product ID sDATA:ValidValue sACDATA:{Expected, But Not Received}~sID:F63 sNAME:SMS Private-Use Fields sDATA:SubfieldLevel sACDATA:8000000000~sID:F63 BMP sNAME:Bitmap sDATA:ValidValue sACDATA:800000~sID:F63.1 sNAME:Network Identification Code sDATA:ValidValue sACDATA:0000^Case 5.1 Authorization - Unspecified Account^VSDC POS Orig Auth 0100 In Req
'''

    parsed_messages = parse_inovant_log(log_string)
    xml_root = generate_emvco_l3_xml(parsed_messages)

    # Write to file
    with open("emvco_output.xml", "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(ET.tostring(xml_root, pretty_print=True, encoding="utf-8"))

    print("✅ XML written to emvco_output.xml")