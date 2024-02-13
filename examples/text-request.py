#!/usr/bin/env python3
# This example shows how to send TextRequest

import sys

from scapy.supersocket import StreamSocket
from scapy_iscsi.iscsi import *

login_params = {
    "InitiatorName": "iqn.2023-01.com.example:initiator",
    "SessionType": "Discovery",
    "HeaderDigest": "None",
    "DataDigest": "None",
    "ErrorRecoveryLevel": 0,
    "DefaultTime2Retain": 0,
    "DefaultTime2Wait": 2,
    "MaxRecvDataSegmentLength": 262144,
}

text_params = {
    "SendTargets": "All",
}

if len(sys.argv) != 2:
    print("usage: text_req.py <host>", file=sys.stderr)
    exit(1)

s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

lirq = ISCSI() / LoginRequest(isid=0xB00B, ds=kv2text(login_params))
lirs = s.sr1(lirq)

trq = ISCSI() / TextRequest(cmdsn=lirs.expcmdsn, expstatsn=lirs.statsn+1,
                            itt=0x1, ds=kv2text(text_params))
trs = s.sr1(trq)

lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=trs.expcmdsn)
lors = s.sr1(lorq)
