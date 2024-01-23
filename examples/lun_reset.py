#!/usr/bin/env python3
# This example shows how to make LUN Reset.

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

# установка соединения с удаленным iSCSI таргетом
s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

# отправка запроса на логин
lirq = ISCSI() / LoginRequest(isid=0xB00B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

negotiated = (text2kv(lirs.ds))
chunk1 = b"A" * int(negotiated["FirstBurstLength"])
chunk2 = b"B" * int(negotiated["MaxRecvDataSegmentLength"])
edtl = len(chunk1) + len(chunk2)
nr_blocks = int(edtl / 4096)

cdb = CDB() / READ16(xfer_len=nr_blocks)

wrq = ISCSI() / SCSICommand(flags="RF", itt=0x1, cmdsn=lirs.expcmdsn, edtl=edtl, cdb=cdb, lun=0)
lirs.expcmdsn = lirs.expcmdsn + 2

s.send(wrq)
wrq = ISCSI() / SCSICommand(flags="RF", itt=0x2, cmdsn=lirs.expcmdsn, edtl=edtl, cdb=cdb, lun=0)
s.send(wrq)

lirs.expcmdsn = lirs.expcmdsn + 2
abort = ISCSI(immediate=1) / TMFRequest(function="abort-task", itt=0x2, cmdsn=lirs.expcmdsn,
                                        rtt=0x5, refcmdsn=lirs.expcmdsn-5, lun=0)
s.send(abort)

reset = ISCSI(immediate=1) / TMFRequest(function="lun-reset", itt=0x2, cmdsn=lirs.expcmdsn,
                                        rtt=0xFFFFFFFF, refcmdsn=lirs.expcmdsn, lun=0)
s.send(reset)

lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=lirs.expcmdsn)
lors = s.sr1(lorq)
