#!/usr/bin/env python3
# This example shows how to invoke the ACA condition

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
    print("usage: aca-condition.py <host>", file=sys.stderr)
    exit(1)

s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

lirq = ISCSI() / LoginRequest(isid=0xB00B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

block_size = 4096
block_count = 1

negotiated = (text2kv(lirs.ds))
chunk1 = bytes([0x00]*block_size * block_count)
edtl = len(chunk1)
nr_blocks = int(edtl / block_size)

# sending the INQUIRY with non-existent page_code and NACA control byte to invoke the ACA condition
cdb = CDB() / INQUIRY(evpd=1, pc=0xFF, alloc_len=4096, control=0x04)
inquiry = ISCSI() / SCSICommand(flags="RF", itt=0x1, cmdsn=lirs.expcmdsn,
                                edtl=edtl, cdb=cdb, lun=1)
inc = s.sr1(inquiry)

# sending WRITE when ACA state is active
cdb_wr = CDB() / WRITE16(xfer_len=nr_blocks)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=inc.expcmdsn,
                            edtl=edtl, cdb=cdb_wr, ds=chunk1, lun=1)
wrs = s.sr1(wrq)

# clearing ACA using LUN reset
clear_aca = ISCSI(immediate=1) / TMFRequest(function="clear-aca", itt=0x2,
                                            cmdsn=wrs.expcmdsn, rtt=0xFFFFFFFF,
                                            refcmdsn=wrs.expcmdsn, lun=1)
clear = s.sr1(clear_aca)

# sending successful WRITE
cdb_wr_2 = CDB() / WRITE16(xfer_len=nr_blocks)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=clear.expcmdsn,
                            edtl=edtl, cdb=cdb_wr_2, ds=chunk1, lun=1)
wrs_2 = s.sr1(wrq)

lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=wrs_2.expcmdsn)
lors = s.sr1(lorq)
