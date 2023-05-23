# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) Daria Bukharina <d.bukharina@yadro.com>
# Copyright (C) Konstantin Shelekhin <k.shelekhin@yadro.com>

"""
iSCSI (Internet Small Computer System Interface).
"""

from scapy.fields import *
from scapy.packet import Packet, bind_layers

LOGIN_STAGES = {
    0x00: "security-negotiation",
    0x01: "login-operational-negotiation",
    0x03: "full-feature-phase",
}

TASK_ATTRIBUTES = {
    0x00: "untagged",
    0x01: "simple",
    0x02: "ordered",
    0x03: "head-of-queue",
    0x04: "aca",
}

REJECT_REASONS = {
    0x01: "reserved",
    0x02: "data-digest-error",
    0x03: "snack-reject",
    0x04: "protocol-error",
    0x05: "not-supported",
    0x06: "immediate-reject",
    0x07: "task-in-progress",
    0x08: "invalid-data-ack",
    0x09: "invalid-pdu-field",
    0x0A: "out-of-resources",
    0x0C: "waiting-for-logout",
}

SERVICE_RESPONSES = {
    0x00: "completed",
    0x01: "target-failure",
}

SCSI_STATUS_CODES = {
    0x00: "good",
    0x02: "check-condition",
    0x04: "condition-met",
    0x08: "busy",
    0x18: "reservation-conflict",
    0x28: "task-full",
    0x30: "aca-active",
    0x40: "task-aborted",
}

TASK_MGMT_FUNCTIONS = {
    0x01: "abort-task",
    0x02: "abort-task-set",
    0x03: "clear-aca",
    0x04: "clear-task-set",
    0x05: "lun-reset",
    0x06: "target-warm-reset",
    0x07: "target-cold-reset",
    0x08: "task-reassign",
    0x09: "query-task",
    0x0A: "query-task-set",
    0x0B: "i-t-nexus-reset",
    0x0C: "query-asynchronous-event",
}

TMF_RESPONSES = {
    0x00: "complete",
    0x01: "task-does-not-exist",
    0x02: "lun-does-not-exist",
    0x03: "task-still-allegiant",
    0x04: "realligiance-not-supported",
    0x05: "not-supported",
    0x06: "authorization-failed",
    0xFF: "rejected",
}


def kv2text(kv):
    return "\x00".join([x[0] + "=" + str(x[1]) for x in list(kv.items())]) + "\x00"


def text2kv(text):
    return dict([tuple(x.split("=")) for x in text.decode("utf-8").split("\x00")][:-1])


class ISCSI(Packet):
    name = "iSCSI PDU"

    show_indent = 0

    fields_desc = [
        BitField("reserved", 0, 1),
        BitField("immediate", 0, 1),
        XBitField("opcode", 0x0, 6),
    ]

    def answers(self, other):
        return self.payload.answers(other.payload)


#
# Initiator Opcodes
#


class NopOut(Packet):
    name = "iSCSI Nop-Out"

    fields_desc = [
        FlagsField("flags", 0x1, 1, "F"),
        XBitField("reserved1", 0x0, 23),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0, 64),
        XBitField("itt", 0x0, 32),
        XBitField("ttt", 0xFFFFFFFF, 32),
        XBitField("cmdsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("reserved2", 0x0, 128),
        # PacketField("hdr_digest", None, Packet),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
        # PacketField("ds_digest", None, Packet),
    ]

    def answers(self, other):
        if self.itt == 0xFFFFFFFF:
            return 1
        return 0


class SCSICommand(Packet):
    name = "iSCSI SCSI Command"

    fields_desc = [
        FlagsField("flags", 0x18, 5, "43WRF"),
        BitEnumField("attrs", 0x1, 3, TASK_ATTRIBUTES),
        XBitField("reserved2", 0x0, 16),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0, 64),
        XBitField("itt", 0x0, 32),
        BitField("edtl", 0, 32),
        XBitField("cmdsn", 0x0, 32),
        XBitField("expstatsn", 0x0, 32),
        PacketField("cdb", None, Packet),
        PacketField("ahs", None, Packet),
        # PacketField("hdr_digest", None, Packet),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
        # PacketField("ds_digest", None, Packet),
    ]

    def answers(self, other):
        return 0


class TMFRequest(Packet):
    name = "iSCSI TMF Request"

    fields_desc = [
        FlagsField("flags", 0x1, 1, "F"),
        BitEnumField("function", 0x00, 7, TASK_MGMT_FUNCTIONS),
        XBitField("reserved1", 0x0, 16),
        BitField("ahs_len", 0, 8),
        BitField("ds_len", 0, 24),
        XBitField("lun", 0, 64),
        BitField("itt", 0, 32),
        BitField("rtt", 0, 32),
        XBitField("cmdsn", 0x0, 32),
        XBitField("expstatsn", 0x0, 32),
        XBitField("refcmdsn", 0x0, 32),
        XBitField("expdatasn", 0x0, 32),
        XBitField("reserved2", 0x0, 64),
    ]

    def answers(self, other):
        return 0


class LoginRequest(Packet):
    name = "iSCSI Login Request"

    fields_desc = [
        FlagsField("flags", 0x2, 2, "CT"),
        XBitField("reserved1", 0x0, 2),
        BitEnumField("csg", 0x1, 2, LOGIN_STAGES),
        BitEnumField("nsg", 0x3, 2, LOGIN_STAGES),
        BitField("version_max", 0, 8),
        BitField("version_min", 0, 8),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("isid", 0x0, 48),
        XBitField("tsih", 0, 16),
        XBitField("itt", 0, 32),
        XBitField("cid", 0, 16),
        XBitField("reserved2", 0, 16),
        XBitField("cmdsn", 0x1, 32),
        XBitField("expstatsn", 0x1, 32),
        XBitField("reserved3", 0x0, 128),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
    ]

    def answers(self, other):
        return 0


class DataOut(Packet):
    name = "iSCSI Data-Out"

    fields_desc = [
        FlagsField("flags", 0x1, 1, "F"),
        XBitField("reserved1", 0x0, 23),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0x0, 64),
        XBitField("itt", 0x0, 32),
        XBitField("ttt", 0xFFFFFFFF, 32),
        XBitField("reserved2", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("reserved3", 0x0, 32),
        XBitField("datasn", 0x0, 32),
        XBitField("offset", 0x0, 32),
        XBitField("reserved4", 0x0, 32),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
    ]

    def answers(self, other):
        if self.ttt == 0xFFFFFFFF:
            return 0
        return 1


bind_layers(ISCSI, NopOut, opcode=0x00)
bind_layers(ISCSI, SCSICommand, opcode=0x01)
bind_layers(ISCSI, TMFRequest, opcode=0x02)
bind_layers(ISCSI, LoginRequest, immediate=1, opcode=0x03)
bind_layers(ISCSI, DataOut, opcode=0x05)

#
# Target Opcodes
#


class NopIn(Packet):
    name = "iSCSI Nop-In"

    fields_desc = [
        FlagsField("flags", 0x1, 1, "F"),
        XBitField("reserved1", 0x0, 23),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0x0, 64),
        XBitField("itt", 0xFFFFFFFF, 32),
        XBitField("ttt", 0x0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("reserved2", 0x0, 96),
        # PacketField("hdr_digest", None, Packet),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
        # PacketField("ds_digest", None, Packet),
    ]

    def answers(self, other):
        if self.itt == 0xFFFFFFFF:
            return 0
        return 1


class SCSIResponse(Packet):
    name = "iSCSI SCSI Response"

    fields_desc = [
        FlagsField("flags", 0x80, 8, "7UOuo21F"),
        BitEnumField("response", 0x0, 8, SERVICE_RESPONSES),
        BitEnumField("status", 0x0, 8, SCSI_STATUS_CODES),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("reserved", 0x0, 64),
        XBitField("itt", 0, 32),
        XBitField("snack_tag", 0x0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("expdatasn", 0x0, 32),
        BitField("brrc", 0, 32),
        BitField("rc", 0, 32),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
    ]

    def answers(self, other):
        return 1


class TMFResponse(Packet):
    name = "iSCSI TMF Response"

    fields_desc = [
        FlagsField("flags", 0x1, 1, "F"),
        XBitField("reserved1", 0x0, 7),
        BitEnumField("response", 0x0, 8, TMF_RESPONSES),
        XBitField("reserved2", 0x0, 8),
        BitField("ahs_len", 0, 8),
        BitField("ds_len", 0, 24),
        XBitField("reserved3", 0x0, 64),
        XBitField("itt", 0, 32),
        XBitField("reserved4", 0x0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("reserved5", 0x0, 96),
        # PacketField("hdr_digest", None, Packet),
    ]

    def answers(self, other):
        return 1


class LoginResponse(Packet):
    name = "iSCSI Login Response"

    fields_desc = [
        FlagsField("flags", 0x0, 2, "CT"),
        XBitField("reserved1", 0, 2),
        BitEnumField("csg", 0x0, 2, LOGIN_STAGES),
        BitEnumField("nsg", 0x0, 2, LOGIN_STAGES),
        BitField("version_max", 0, 8),
        BitField("version_active", 0, 8),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("isid", 0, 48),
        XBitField("tsih", 0, 16),
        XBitField("itt", 0, 32),
        XBitField("reserved2", 0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("status_class", 0x0, 8),
        XBitField("status_detail", 0x0, 8),
        XBitField("reserved3", 0, 80),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
    ]

    def answers(self, other):
        return 1


class DataIn(Packet):
    name = "iSCSI Data-In"

    fields_desc = [
        FlagsField("flags", 0x0, 8, "SUO432AF"),
        XBitField("reserved1", 0x0, 8),
        BitEnumField("status", 0x0, 8, SCSI_STATUS_CODES),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0x0, 64),
        XBitField("itt", 0x0, 32),
        XBitField("ttt", 0xFFFFFFFF, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("datasn", 0x0, 32),
        XBitField("offset", 0x0, 32),
        XBitField("rc", 0x0, 32),
        # PacketField("hdr_digest", None, Packet),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
        # PacketField("ds_digest", None, Packet),
    ]

    def answers(self, other):
        # TODO: Check RFC
        return 1


class Reject(Packet):
    name = "iSCSI Reject"

    fields_desc = [
        FlagsField("flags", 0x01, 1, "F"),
        XBitField("reserved1", 0x0, 7),
        BitEnumField("reason", 0x0, 8, REJECT_REASONS),
        XBitField("reserved2", 0x0, 8),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("reserved3", 0x0, 64),
        XBitField("itt", 0xFFFFFFFF, 32),
        XBitField("reserved4", 0x0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("datasn", 0x0, 32),
        XBitField("reserved5", 0x0, 64),
        # PacketField("hdr_digest", None, Packet),
        PadField(StrLenField("ds", None, length_from=lambda pkt: pkt.ds_len), 4),
        # PacketField("ds_digest", None, Packet),
    ]

    def answers(self, other):
        return 1


class R2T(Packet):
    name = "iSCSI R2T"

    fields_desc = [
        FlagsField("flags", 0x01, 1, "F"),
        XBitField("reserved", 0x0, 23),
        BitField("ahs_len", 0, 8),
        BitFieldLenField("ds_len", None, 24, length_of="ds"),
        XBitField("lun", 0, 64),
        XBitField("itt", 0x0, 32),
        XBitField("ttt", 0x0, 32),
        XBitField("statsn", 0x0, 32),
        XBitField("expcmdsn", 0x0, 32),
        XBitField("maxcmdsn", 0x0, 32),
        XBitField("r2tsn", 0x0, 32),
        XBitField("offset", 0x0, 32),
        XBitField("ddtl", 0x0, 32),
    ]

    def answers(self, other):
        return 1


bind_layers(ISCSI, NopIn, opcode=0x20)
bind_layers(ISCSI, SCSIResponse, opcode=0x21)
bind_layers(ISCSI, TMFResponse, opcode=0x22)
bind_layers(ISCSI, LoginResponse, opcode=0x23)
bind_layers(ISCSI, DataIn, opcode=0x25)
bind_layers(ISCSI, R2T, opcode=0x31)
bind_layers(ISCSI, Reject, opcode=0x3F)


#
# SCSI Opcodes
#


class CDB(Packet):
    name = "SCSI CDB"

    show_indent = 0

    fields_desc = [
        XBitField("opcode", 0x0, 8),
    ]


class READ16(Packet):
    name = "SCSI READ(16)"

    fields_desc = [
        XBitField("rdprotect", 0x0, 3),
        FlagsField("flags", 0x0, 5, ["BIT0", "BIT1", "RARC", "FUA", "DPO"]),
        XBitField("lba", 0x0, 64),
        XBitField("xfer_len", 0x0, 32),
        XBitField("reserved", 0x0, 3),
        XBitField("group_number", 0x0, 5),
        XBitField("control", 0x0, 8),
    ]


class WRITE16(Packet):
    name = "SCSI WRITE(16)"

    fields_desc = [
        XBitField("wrprotect", 0x0, 3),
        FlagsField("flags", 0x0, 5, ["BIT0", "BIT1", "BIT2", "FUA", "DPO"]),
        XBitField("lba", 0x0, 64),
        XBitField("xfer_len", 0x0, 32),
        XBitField("reserved", 0x0, 3),
        XBitField("group_number", 0x0, 5),
        XBitField("control", 0x0, 8),
    ]


bind_layers(CDB, READ16, opcode=0x88)
bind_layers(CDB, WRITE16, opcode=0x8A)
