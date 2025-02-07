# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = TaZmen Sniffer Protocol (TZSP)
# scapy.contrib.status = loads

"""
    This code is taken from the scapy.contrib repository and little bit rewrited
    Since this part is under development, I decided to copy it to avoid possible import problems in the future.
    If you come across this repository and the TZSP branch in Scapy has been moved to the main one, 
    please make a Pull Request so that I remove this fragment and use the scapy implementation.


    TZSP - TaZmen Sniffer Protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Thomas Tannhaeuser, hecke@naberius.de

    :description:

        This module provides Scapy layers for the TZSP protocol.

        references:
            - https://en.wikipedia.org/wiki/TZSP
            - https://web.archive.org/web/20050404125022/http://www.networkchemistry.com/support/appnotes/an001_tzsp.html  # noqa: E501

    :NOTES:
        - to allow Scapy to dissect this layer automatically, you need to bind the TZSP layer to UDP using  # noqa: E501
          the default TZSP port (0x9090), e.g.

            bind_layers(UDP, TZSP, sport=TZSP_PORT_DEFAULT)
            bind_layers(UDP, TZSP, dport=TZSP_PORT_DEFAULT)

        - packet format definition from www.networkchemistry.com is different from the one given by wikipedia  # noqa: E501
        - seems Wireshark implements the wikipedia protocol version (didn't dive into their code)  # noqa: E501
        - observed (miss)behavior of Wireshark (2.2.6)
          - fails to decode RSSI & SNR using short values - only one byte taken
          - SNR is labeled as silence
          - WlanRadioHdrSerial is labeled as Sensor MAC
          - doesn't know the packet count tag (40 / 0x28)

"""
from scapy.compat import orb
from scapy.error import warning, Scapy_Exception
from scapy.fields import (
    ByteField,
    ShortEnumField,
    IntField,
    FieldLenField,
    YesNoByteField,
    StrLenField,
    ByteEnumField,
    ShortField,
    XStrLenField,
)
from scapy.layers.dot11 import Packet, Dot11, PrismHeader
from scapy.layers.l2 import Ether
from scapy.packet import Raw

TZSP_PORT_DEFAULT = 0x9090

class TZSP(Packet):
    TYPE_RX_PACKET = 0x00
    TYPE_TX_PACKET = 0x01
    TYPE_CONFIG = 0x03
    TYPE_KEEPALIVE = TYPE_NULL = 0x04
    TYPE_PORT = 0x05

    TYPES = {
        TYPE_RX_PACKET: 'RX_PACKET',
        TYPE_TX_PACKET: 'TX_PACKET',
        TYPE_CONFIG: 'CONFIG',
        TYPE_NULL: 'KEEPALIVE/NULL',
        TYPE_PORT: 'PORT',
    }

    ENCAPSULATED_PROTOCOLS = {
        0x01: ('ETHERNET', Ether),
        0x12: ('IEEE 802.11', Dot11),
        0x77: ('PRISM HEADER', PrismHeader),
    }

    fields_desc = [
        ByteField('version', 0x01),
        ByteEnumField('type', TYPE_RX_PACKET, TYPES),
        ShortEnumField('encapsulated_protocol', 0x01, {
            k: v[0] for k, v in ENCAPSULATED_PROTOCOLS.items()
        })
    ]

    def get_encapsulated_payload_class(self):
        """Get class for encapsulated payload"""
        proto = self.ENCAPSULATED_PROTOCOLS.get(self.encapsulated_protocol)
        if proto:
            return proto[1]
        warning(f'Unknown encapsulation type {self.encapsulated_protocol}')
        return Raw

    def guess_payload_class(self, payload):
        if self.type == self.TYPE_KEEPALIVE:
            if payload:
                warning(f'Payload in KEEPALIVE packet: {len(payload)} bytes')
            return Raw
        return _tzsp_guess_next_tag(payload)

    def get_encapsulated_payload(self):
        if self.type not in (self.TYPE_RX_PACKET, self.TYPE_TX_PACKET):
            return None
            
        end_tag = self.payload.getlayer(TZSPTagEnd)
        return end_tag.payload if end_tag else None


def _tzsp_handle_unknown_tag(payload, tag_type):
    if len(payload) < 2:
        warning(f'Invalid tag {tag_type}: packet too short')
        return Raw

    tag_len = orb(payload[1])
    if tag_len + 2 > len(payload):
        warning(f'Invalid tag {tag_type}: length mismatch')
        return Raw

    warning(f'Unknown tag type {tag_type}')
    return TZSPTagUnknown


def _tzsp_guess_next_tag(payload):
    if not payload:
        warning('Missing payload')
        return None

    tag_type = orb(payload[0])
    handler = _TZSP_TAG_CLASSES.get(tag_type)

    if isinstance(handler, dict):
        if len(payload) < 2:
            warning('Tag length missing')
            return Raw
        return handler.get(orb(payload[1]), Raw)
    
    return handler or _tzsp_handle_unknown_tag(payload, tag_type)


class _TZSPTag(Packet):
    TAG_TYPES = {
        0x00: 'PADDING',
        0x01: 'END',
        0x0a: 'RAW_RSSI',
        0x0b: 'SNR',
        0x0c: 'DATA_RATE',
        0x0d: 'TIMESTAMP',
        0x0f: 'CONTENTION_FREE',
        0x10: 'DECRYPTED',
        0x11: 'FCS_ERROR',
        0x12: 'RX_CHANNEL',
        0x28: 'PACKET_COUNT',
        0x29: 'RX_FRAME_LENGTH',
        0x3c: 'WLAN_RADIO_HDR_SERIAL'
    }

    def guess_payload_class(self, payload):
        return _tzsp_guess_next_tag(payload)


class TZSPStructureException(Scapy_Exception):
    pass


class TZSPTagEnd(Packet):
    fields_desc = [ByteEnumField('type', 0x01, _TZSPTag.TAG_TYPES)]

    def guess_payload_class(self, payload):
        """
        the type of the payload encapsulation is given be the outer TZSP layers attribute encapsulation_protocol  # noqa: E501
        """

        under_layer = self.underlayer
        tzsp_header = None

        while under_layer:
            if isinstance(under_layer, TZSP):
                tzsp_header = under_layer
                break
            under_layer = under_layer.underlayer

        if tzsp_header:
            return tzsp_header.get_encapsulated_payload_class()
        else:
            raise TZSPStructureException('missing parent TZSP header')


class TZSPTagPadding(_TZSPTag):
    fields_desc = [ByteEnumField('type', 0x00, _TZSPTag.TAG_TYPES)]


class TZSPTagRawRSSIByte(_TZSPTag):
    """
    relative received signal strength - signed byte value
    """
    fields_desc = [
        ByteEnumField('type', 0x0a, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteField('raw_rssi', 0)
    ]


class TZSPTagRawRSSIShort(_TZSPTag):
    """
    relative received signal strength - signed short value
    """
    fields_desc = [
        ByteEnumField('type', 0x0a, _TZSPTag.TAG_TYPES),
        ByteField('len', 2),
        ShortField('raw_rssi', 0)
    ]


class TZSPTagSNRByte(_TZSPTag):
    """
    signal noise ratio - signed byte value
    """
    fields_desc = [
        ByteEnumField('type', 0x0b, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteField('snr', 0)
    ]


class TZSPTagSNRShort(_TZSPTag):
    """
    signal noise ratio - signed short value
    """
    fields_desc = [
        ByteEnumField('type', 0x0b, _TZSPTag.TAG_TYPES),
        ByteField('len', 2),
        ShortField('snr', 0)
    ]

class TZSPTagDataRate(_TZSPTag):
    DATA_RATES = {
        0x00: 'unknown',
        0x02: '1 MB/s', 0x04: '2 MB/s', 0x0B: '5.5 MB/s',
        0x0C: '6 MB/s', 0x12: '9 MB/s', 0x16: '11 MB/s',
        0x18: '12 MB/s', 0x24: '18 MB/s', 0x2C: '22 MB/s',
        0x30: '24 MB/s', 0x42: '33 MB/s', 0x48: '36 MB/s',
        0x60: '48 MB/s', 0x6C: '54 MB/s', 0x0A: '1 MB/s (legacy)',
        0x14: '2 MB/s (legacy)', 0x37: '5.5 MB/s (legacy)',
        0x6E: '11 MB/s (legacy)'
    }
    fields_desc = [
        ByteEnumField('type', 0x0c, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteEnumField('data_rate', 0x00, DATA_RATES)
    ]


class TZSPTagTimestamp(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x0d, _TZSPTag.TAG_TYPES),
        ByteField('len', 4),
        IntField('timestamp', 0)
    ]


class TZSPTagContentionFree(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x0f, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        YesNoByteField('contention_free', 0)
    ]


class TZSPTagDecrypted(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x10, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        YesNoByteField('decrypted', 0, config={'yes': 0, 'no': (1, 0xff)})
    ]


class TZSPTagError(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x11, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        YesNoByteField('fcs_error', 0, config={'no': 0, 'yes': 1, 'reserved': (2, 0xff)})
    ]


class TZSPTagRXChannel(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x12, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteField('rx_channel', 0)
    ]


class TZSPTagPacketCount(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x28, _TZSPTag.TAG_TYPES),
        ByteField('len', 4),
        IntField('packet_count', 0)
    ]


class TZSPTagRXFrameLength(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x29, _TZSPTag.TAG_TYPES),
        ByteField('len', 2),
        ShortField('rx_frame_length', 0)
    ]


class TZSPTagWlanRadioHdrSerial(_TZSPTag):
    fields_desc = [
        ByteEnumField('type', 0x3c, _TZSPTag.TAG_TYPES),
        FieldLenField('len', None, length_of='sensor_id', fmt='B'),
        StrLenField('sensor_id', '', length_from=lambda pkt: pkt.len)
    ]


class TZSPTagUnknown(_TZSPTag):
    fields_desc = [
        ByteField('type', 0xff),
        FieldLenField('len', None, length_of='data', fmt='B'),
        XStrLenField('data', '', length_from=lambda pkt: pkt.len)
    ]


_TZSP_TAG_CLASSES = {
    0x00: TZSPTagPadding,
    0x01: TZSPTagEnd,
    0x0a: {1: TZSPTagRawRSSIByte, 2: TZSPTagRawRSSIShort},
    0x0b: {1: TZSPTagSNRByte, 2: TZSPTagSNRShort},
    0x0c: TZSPTagDataRate,
    0x0d: TZSPTagTimestamp,
    0x0f: TZSPTagContentionFree,
    0x10: TZSPTagDecrypted,
    0x11: TZSPTagError,
    0x12: TZSPTagRXChannel,
    0x28: TZSPTagPacketCount,
    0x29: TZSPTagRXFrameLength,
    0x3c: TZSPTagWlanRadioHdrSerial
}
