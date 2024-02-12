#!/usr/bin/env python3
#
# DESCRIPTION
#
# This example shows how to make SCSI-3 PR_OUT PREEMPT_AND_ABORT command
# For it to work session #1 (regulated by InitiatorName + isid in LoginRequest) makes a reservation
# and session #2 preempts it, note that it requires 'service_action_res_key' set to the key
# with which previous reservation was made (set in res_key_to_remove)

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
lirq = ISCSI() / LoginRequest(isid=0xA00B, ds=kv2text(proposed_params))
lirs = s.sr1(lirq)

res_key = 0xabc111

# PR OUT with register key
cdb_reg_key = CDB() / PR_OUT()
params_reg_key = PR_OUT_PARAMS(sa_res_key=res_key)
edtl = len(params_reg_key)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=lirs.expcmdsn, edtl=edtl, cdb=cdb_reg_key,
                            ds=params_reg_key, lun=lun)
pr_out_reg_key = s.sr1(wrq)

# PR OUT - reserve
cdb_res = CDB() / PR_OUT(sa="reserve", type="write_excl")
params_res = PR_OUT_PARAMS(res_key=res_key)
edtl = len(params_res)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=pr_out_reg_key.expcmdsn, edtl=edtl,
                            cdb=cdb_res, ds=params_res, lun=lun)
pr_out_res = s.sr1(wrq)

# Logout - session #1
lorq = ISCSI() / LogoutRequest(itt=0x2, cmdsn=pr_out_res.expcmdsn)
lors = s.sr1(lorq)

# reopen scsi connection
s.close()
s = socket.socket()
s.connect((sys.argv[1], 3260))
s = StreamSocket(s, ISCSI)

# Login - session #2
lirq2 = ISCSI() / LoginRequest(isid=0xA016, ds=kv2text(proposed_params))
lirs2 = s.sr1(lirq2)

res_key_to_remove = res_key
res_key = 0xabc222

# PR OUT with register key
cdb_reg_key = CDB() / PR_OUT()
params_reg_key = PR_OUT_PARAMS(sa_res_key=res_key)
edtl = len(params_reg_key)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=lirs2.expcmdsn, edtl=edtl, cdb=cdb_reg_key,
                            ds=params_reg_key, lun=lun)
pr_out_reg_key = s.sr1(wrq)

# PR OUT with preempt and abort
cdb_preempt = CDB() / PR_OUT(sa="preempt_and_abort", type="write_excl")
params_preempt = PR_OUT_PARAMS(res_key=res_key, sa_res_key=res_key_to_remove)
edtl = len(params_preempt)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=pr_out_reg_key.expcmdsn, edtl=edtl,
                            cdb=cdb_preempt, ds=params_preempt, lun=lun)
pr_out_preempt = s.sr1(wrq)

# PR IN with read keys -- does not actually get any info it receives 'Unit attention'
# with 'Registration preempted' message from previous command
cdb_rk = CDB() / PR_IN()
edtl = cdb_rk.allocation_len
wrq = ISCSI() / SCSICommand(flags="FR", itt=0x1, cmdsn=pr_out_preempt.expcmdsn, edtl=edtl,
                            cdb=cdb_rk, lun=lun)
pr_in_rk = s.sr1(wrq)

# PR OUT - release
cdb_rel2 = CDB() / PR_OUT(sa="release", type="write_excl")
params_rel2 = PR_OUT_PARAMS(res_key=res_key)
edtl = len(params_rel2)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=pr_in_rk.expcmdsn, edtl=edtl,
                            cdb=cdb_rel2, ds=params_rel2, lun=lun)
pr_out_rel2 = s.sr1(wrq)

# PR OUT with unregister key (sending 0s from the same session)
cdb_unreg = CDB() / PR_OUT()
params_unreg = PR_OUT_PARAMS(res_key=res_key)
edtl_unreg = len(params_unreg)
wrq = ISCSI() / SCSICommand(flags="WF", itt=0x1, cmdsn=pr_out_rel2.expcmdsn, edtl=edtl_unreg,
                            cdb=cdb_unreg, ds=params_unreg, lun=lun)
pr_out_unreg = s.sr1(wrq)

# Logout - session #2
lorq2 = ISCSI() / LogoutRequest(itt=0x2, cmdsn=pr_out_unreg.expcmdsn)
lors2 = s.sr1(lorq2)
