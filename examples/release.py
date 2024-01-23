#!/usr/bin/env python3
# This example shows how to write data with WRITE(16) and also includes RESERVE and RELEASE commands.

import sys
from scapy.supersocket import StreamSocket
from scapy_iscsi.iscsi import *

proposed_params = {
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

if len(sys.argv) != 2:
    print("usage: write.py <host>", file=sys.stderr)
    exit(1)

s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

# Login
lirq = ISCSI() / LoginRequest(isid=0xB00B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

negotiated = text2kv(lirs.ds)

cdb = CDB() / RELEASE(lun=0x0001000000000000)

wrq = ISCSI() / SCSICommand(flags="F", itt=0x1, cmdsn=lirs.expcmdsn, cdb=cdb, lun=0x0001000000000000)
reserve = s.sr1(wrq)

# Logout
lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=reserve.expcmdsn)
lors = s.sr1(lorq)
