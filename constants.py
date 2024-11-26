# ######################################################################## #
# References:                                                              #
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml   #
# ######################################################################## #

from enum import IntEnum

RAW_DATA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
IP_HEADER_SIZE = 20
ICMP_HEADER_SIZE = 8
TIMESTAMP_SIZE = 8
TTL = 64
TIMEOUT = 30
DEFAULT_COUNT = 4
LOCALHOST = "127.0.0.1"

class ICMPType(IntEnum):
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11

# ICMP Codes for Type 3 (Destination Unreachable)
class ICMPCodeDestUnreach(IntEnum):
    NET_UNREACH = 0
    HOST_UNREACH = 1
    PROTOCOL_UNREACH = 2
    PORT_UNREACH = 3
    FRAG_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    NET_UNKNOWN = 6
    HOST_UNKNOWN = 7
    ISOLATED = 8
    NET_PROHIBITED = 9
    HOST_PROHIBITED = 10
    TOS_NET_UNREACH = 11
    TOS_HOST_UNREACH = 12
    COMM_ADMIN_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF = 15

# ICMP Codes for Type 11 (Time Exceeded)
class ICMPCodeTimeExceeded(IntEnum):
    TTL_EXCEEDED_TRANSIT = 0
    FRAG_REASSEMBLY_TIME_EXCEEDED = 1

ICMP_MESSAGES = {
    # Type 3: Destination Unreachable
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.NET_UNREACH): "Network Unreachable",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.HOST_UNREACH): "Host Unreachable",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.PROTOCOL_UNREACH): "Protocol Unreachable",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.PORT_UNREACH): "Port Unreachable",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.FRAG_NEEDED): "Fragmentation Needed and Don't Fragment was Set",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.SOURCE_ROUTE_FAILED): "Source Route Failed",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.NET_UNKNOWN): "Destination Network Unknown",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.HOST_UNKNOWN): "Destination Host Unknown",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.ISOLATED): "Source Host Isolated",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.NET_PROHIBITED): "Communication with Destination Network is Administratively Prohibited",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.HOST_PROHIBITED): "Communication with Destination Host is Administratively Prohibited",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.TOS_NET_UNREACH): "Destination Network Unreachable for Type of Service",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.TOS_HOST_UNREACH): "Destination Host Unreachable for Type of Service",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.COMM_ADMIN_PROHIBITED): "Communication Administratively Prohibited",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.HOST_PRECEDENCE_VIOLATION): "Host Precedence Violation",
    (ICMPType.DESTINATION_UNREACHABLE, ICMPCodeDestUnreach.PRECEDENCE_CUTOFF): "Precedence Cutoff in Effect",

    # Type 11: Time Exceeded
    (ICMPType.TIME_EXCEEDED, ICMPCodeTimeExceeded.TTL_EXCEEDED_TRANSIT): "TTL Exceeded in Transit",
    (ICMPType.TIME_EXCEEDED, ICMPCodeTimeExceeded.FRAG_REASSEMBLY_TIME_EXCEEDED): "Fragment Reassembly Time Exceeded",
}