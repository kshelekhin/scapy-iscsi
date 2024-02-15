#!/usr/bin/env python3
# This example shows how to make SCSI-3 PR_OUT and PR_IN commands

import sys
from scapy.supersocket import StreamSocket
from scapy_iscsi.iscsi import *

if len(sys.argv) != 2:
    print("usage: scsi3-reservations.py <host>", file=sys.stderr)
    exit(1)

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

s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

lun = 0x0001000000000000

# Login - session #1
lirq = ISCSI() / LoginRequest(isid=0x100B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

res_key = 0xabc111

# PR OUT with register key
cdb = CDB() / PR_OUT()
params = PR_OUT_PARAMS(sa_res_key=res_key)
edtl = len(params)
rq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=lirs.expcmdsn, edtl=edtl, cdb=cdb,
                           ds=params, lun=lun)
rs = s.sr1(rq)

# PR IN with read keys
cdb = CDB() / PR_IN()
edtl = cdb.allocation_len
rq = ISCSI() / SCSICommand(flags="FR", itt=0x2, cmdsn=rs.expcmdsn, edtl=edtl, cdb=cdb, lun=lun)
rs = s.sr1(rq)

# Logout - session #1
lorq = ISCSI() / LogoutRequest(itt=0x3, cmdsn=rs.expcmdsn)
lors = s.sr1(lorq)
