from scapy_iscsi.iscsi import *

def test_login_request_constructor():
    login_parameters = {
        "InitiatorName": "iqn.2023-01.com.example:initiator",
        "TargetName": "iqn.2023-01.com.example:target",
        "SessionType": "Normal",
        "HeaderDigest": "None",
        "DataDigest": "None",
        "ErrorRecoveryLevel": 0,
        "DefaultTime2Retain": 0,
        "DefaultTime2Wait": 2,
        "ImmediateData": "Yes",
        "FirstBurstLength": 65536,
        "MaxBurstLength": 262144,
        "MaxRecvDataSegmentLength": 262144,
        "MaxOutstandingR2T": 1,
    }
    pdu = ISCSI() / LoginRequest(ds=kv2text(login_parameters))
    with open("tests/pdu/login-request", 'br') as f:
       reference = f.read() 
       assert(reference == pdu.build())

def test_scsi_command_constructor():
    cdb = CDB() / WRITE16(xfer_len=1)
    pdu = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=0x1, edtl=512,
                                cdb=cdb, ds=(b'A' * 512))
    with open("tests/pdu/write16", 'br') as f:
       reference = f.read() 
       assert(reference == pdu.build())
