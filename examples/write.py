#!/usr/bin/env python3
# This example shows how to write data with WRITE(16)

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

negotiated = (text2kv(lirs.ds))

chunk1 = b"A" * int(negotiated["FirstBurstLength"])
chunk2 = b"B" * int(negotiated["MaxRecvDataSegmentLength"])
edtl = len(chunk1) + len(chunk2)
nr_blocks = int(edtl / 512)

cdb = CDB() / WRITE16(xfer_len=nr_blocks)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=lirs.expcmdsn, edtl=edtl, cdb=cdb, ds=chunk1)
r2t = s.sr1(wrq)
dto = ISCSI() / DataOut(itt=0x1, ttt=r2t.ttt, offset=r2t.offset, ds=chunk2)
wrs = s.sr1(dto)

lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=wrs.expcmdsn)
lors = s.sr1(lorq)
