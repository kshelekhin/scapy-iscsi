#!/usr/bin/env python3
# This example shows how to take SCSI2 reservations

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

lirq = ISCSI() / LoginRequest(isid=0xB00B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

negotiated = text2kv(lirs.ds)

cdb_reserve = CDB() / RESERVE(lun=0)

wrq = ISCSI() / SCSICommand(flags="F", itt=0x1, cmdsn=lirs.expcmdsn, cdb=cdb_reserve, lun=0)
reserve = s.sr1(wrq)

cdb_release = CDB() / RELEASE(lun=0)

wrq = ISCSI() / SCSICommand(flags="F", itt=0x1, cmdsn=reserve.expcmdsn, cdb=cdb_release, lun=0)
release = s.sr1(wrq)

lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=release.expcmdsn)
lors = s.sr1(lorq)
