# ##################################################################
# IcmpPacket builds the ICMP packet and sends it to the target host.
# ##################################################################

import struct
import sys
import time
from socket import *
import select
from statistics import Statistics
from echo_reply import EchoReply
from constants import (
    ICMPType,
    ICMPCodeDestUnreach,
    ICMPCodeTimeExceeded,
    ICMP_MESSAGES,
    RAW_DATA,
    TTL,
    TIMEOUT,
    IP_HEADER_SIZE,
    LOCALHOST
)

class IcmpPacket:
    def __init__(self, statistics: Statistics, debug: bool = False):
        self.__icmpTarget: str = ""                # Remote Host
        self.__destinationIpAddress: str = ""      # Remote Host IP Address
        self.__header: bytes = b""                 # Header after byte packing
        self.__data: bytes = b""                   # Data after encoding
        self.__dataRaw: str = ""                   # Raw string data before encoding
        self.__icmpType: int = 0                   # 0-255 (unsigned char)
        self.__icmpCode: int = 0                   # 0-255 (unsigned char)
        self.__packetChecksum: int = 0             # 0-65535 (unsigned short)
        self.__packetIdentifier: int = 0           # 0-65535 (unsigned short)
        self.__packetSequenceNumber: int = 0       # 0-65535 (unsigned short)
        self.__ipTimeout: int = TIMEOUT            # Timeout for receiving packets
        self.__ttl: int = TTL                      # Time to live
        self.__statistics: Statistics = statistics # Statistics object
        self.__debug: bool = debug                 # Debug flag

    # ############################################################
    # Setter                                                     #
    # ############################################################
    def set_icmp_target(self, icmpTarget: str):
        self.__icmpTarget = icmpTarget.strip()
        if self.__icmpTarget:
            self.__destinationIpAddress = gethostbyname(self.__icmpTarget)
        else:
            self.__destinationIpAddress = LOCALHOST

    # ############################################################
    # Public Functions                                           #
    # ############################################################
    def build_echo_request_packet(self, packetIdentifier: int, packetSequenceNumber: int):
        self.__icmpType = ICMPType.ECHO_REQUEST
        self.__icmpCode = 0
        self.__packetIdentifier = packetIdentifier
        self.__packetSequenceNumber = packetSequenceNumber
        self.__dataRaw = RAW_DATA
        self.__pack_and_recalculate_checksum()

    def send_echo_request(self):
        self.__statistics.increment_packets_sent()

        try:
            # Create a new raw socket for each request
            with socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
                s.settimeout(self.__ipTimeout)
                s.bind(("", 0)) # Bind to any available interface
                s.setsockopt(IPPROTO_IP, IP_TTL, struct.pack("I", self.__ttl))

                s.sendto(self.__header + self.__data, (self.__destinationIpAddress, 0)) # ICMP doesn't use port numbers
                ping_start_time = time.time()

                # Wait for the response
                ready = select.select([s], [], [], self.__ipTimeout)
                if not ready[0]:  # Timeout
                    self.__statistics.increment_packet_errors()
                    print("  *        *        *        *        *    Request timed out.")
                    return

                recv_packet, addr = s.recvfrom(1024)
                time_received = time.time()

                rtt = (time_received - ping_start_time) * 1000
                self.__statistics.update_rtt(rtt)

                icmp_type = recv_packet[IP_HEADER_SIZE]
                icmp_code = recv_packet[IP_HEADER_SIZE + 1]

                if icmp_type == ICMPType.ECHO_REPLY:
                    echo_reply = EchoReply(recv_packet, self.__statistics, self.__debug)
                    self.__validate_reply(echo_reply)
                    echo_reply.print_result_to_console(self.__ttl, time_received, addr, self)
                elif icmp_type in [ICMPType.DESTINATION_UNREACHABLE, ICMPType.TIME_EXCEEDED]:
                    self.__statistics.increment_packet_errors()
                    message = self.__get_icmp_message(icmp_type, icmp_code)
                    print(f"From {addr[0]}: icmp_type={icmp_type} icmp_code={icmp_code} - {message}")
                else:
                    print("  Unknown ICMP Type received.")

        except PermissionError:
            print("Permission denied: You need to run this script with root privilege.")
            sys.exit(1)
        except timeout:
            self.__statistics.increment_packet_errors()
            print("  *        *        *        *        *    Request timed out (By Exception).")
        except Exception as e:
            self.__statistics.increment_packet_errors()
            print(f"Exception occurred: {e}")

    def print_icmp_packet_header_hex(self):
        header_size = len(self.__header)
        hex_strings = [f"i={i+1}: {self.__header[i:i+1].hex()}" for i in range(header_size)]
        content = " | ".join(hex_strings)

        print("Header Size:", header_size)
        print(content)

    def print_icmp_packet_data_hex(self):
        data_size = len(self.__data)
        hex_strings = [f"i={i+1}: {self.__data[i:i+1].hex()}" for i in range(data_size)]
        bytes_per_row = 8
        rows = [hex_strings[j:j+bytes_per_row] for j in range(0, data_size, bytes_per_row)]
        
        print("Data Size:", data_size)
        for row in rows:
            content = " | ".join(row)
            print(content)

    def print_icmp_packet_hex(self):
        print("===== ICMP packet in hex =====")
        self.print_icmp_packet_header_hex()
        print()
        self.print_icmp_packet_data_hex()
        print("===== End of ICMP packet in hex =====\n")

    # ############################################################
    # Private Functions                                          #
    # ############################################################
    def __recalculate_checksum(self):
        if self.__debug:
            print("Calculating Checksum...")
        packet_as_bytes = self.__header + self.__data
        checksum = 0
        count_to = (len(packet_as_bytes) // 2) * 2

        count = 0
        while count < count_to:
            this_val = packet_as_bytes[count + 1] * 256 + packet_as_bytes[count]
            checksum += this_val
            checksum &= 0xFFFFFFFF
            count += 2

        if count_to < len(packet_as_bytes):
            this_val = packet_as_bytes[-1]
            checksum += this_val
            checksum &= 0xFFFFFFFF

        # Add carry bits
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        # One's complement
        answer = ~checksum & 0xFFFF
        # Swap bytes for little endian systems
        answer = (answer >> 8) | (answer << 8 & 0xFF00)
        if self.__debug:
            print("Checksum: ", hex(answer))

        self.__packetChecksum = answer

    def __pack_header(self):
        # Pack the header with network byte order (big-endian)
        self.__header = struct.pack(
            "!BBHHH",
            self.__icmpType,              # ex: 8
            self.__icmpCode,              # ex: 0
            self.__packetChecksum,        # ex: 0x1c2d
            self.__packetIdentifier,      # ex: 12345
            self.__packetSequenceNumber   # ex: 1
        )
        if self.__debug:
            # b'\x08\x00\x1c-\x30\x39\x00\x01'
            print(f"Packed Header:  {self.__header}")

    def __encode_data(self):
        # Storing send time information in the data field of the ICMP packet
        # is often used as a techinque to calculate the RTT
        # since it can be extracted from the reply packet.
        timestamp = struct.pack("!d", time.time())
        data_raw_encoded = self.__dataRaw.encode("utf-8")
        self.__data = timestamp + data_raw_encoded

    def __pack_and_recalculate_checksum(self):
        self.__encode_data()
        self.__pack_header()
        self.__recalculate_checksum()
        self.__pack_header()  # Re-pack header with the new checksum

    def __validate_reply(self, echo_reply_packet: EchoReply):
        checkFlag = True

        # Check sequence number
        if self.__packetSequenceNumber != echo_reply_packet.get_icmp_sequence_number():
            checkFlag = False
            if self.__debug:
                print(
                    f"Packet Sequence number expected: {self.__packetSequenceNumber}, "
                    f"received: {echo_reply_packet.get_icmp_sequence_number()}"
                )
            echo_reply_packet.set_icmp_sequence_number_is_valid(False)
        else:
            echo_reply_packet.set_icmp_sequence_number_is_valid(True)

        # Check identifier
        if self.__packetIdentifier != echo_reply_packet.get_icmp_identifier():
            checkFlag = False
            if self.__debug:
                print(
                    f"Packet Identifier expected: {self.__packetIdentifier}, "
                    f"received: {echo_reply_packet.get_icmp_identifier()}"
                )
            echo_reply_packet.set_icmp_identifier_is_valid(False)
        else:
            echo_reply_packet.set_icmp_identifier_is_valid(True)

        # Check raw data
        if self.__dataRaw != echo_reply_packet.get_icmp_data():
            checkFlag = False
            if self.__debug:
                print(
                    f"Raw Data expected: {self.__dataRaw}, "
                    f"received: {echo_reply_packet.get_icmp_data()}"
                )
            echo_reply_packet.set_icmp_raw_data_is_valid(False)
        else:
            echo_reply_packet.set_icmp_raw_data_is_valid(True)

        echo_reply_packet.set_is_valid_response(checkFlag)

    def __get_icmp_message(self, icmp_type: int, icmp_code: int) -> str:
        """Retrieves the ICMP message based on type and code."""
        key = (ICMPType(icmp_type), icmp_code) if icmp_code is not None else (ICMPType(icmp_type), None)
        message = ICMP_MESSAGES.get(key, "Unknown ICMP Type or Code")
        
        if self.__debug:
            print(f"ICMP Type: {icmp_type}, Code: {icmp_code}, Message: {message}")
        
        return message