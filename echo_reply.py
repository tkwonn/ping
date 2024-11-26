# ############################################################################################################ #
# EchoReply unpacks the received packet and prints the result to the console.                                  #
# ############################################################################################################ #

import struct
from statistics import Statistics
from constants import IP_HEADER_SIZE, ICMP_HEADER_SIZE, TIMESTAMP_SIZE

class EchoReply:
    def __init__(self, recvPacket: bytes, statistics: Statistics, debug: bool = False):
        self.__recvPacket: bytes = recvPacket
        self.__statistics: Statistics = statistics
        self.__isValidResponse: bool = False
        self.__IcmpIdentifier_isValid: bool = True
        self.__IcmpSequenceNumber_isValid: bool = True
        self.__IcmpRawData_isValid: bool = True
        self.__DEBUG_EchoReply: bool = debug

    # ############################################################################################################ #
    # Getters　　　　　　　　　                                                                                       #
    # ############################################################################################################ #
    def get_icmp_type(self) -> int:
        return self.__unpack_by_format_and_position("B", IP_HEADER_SIZE)

    def get_icmp_code(self) -> int:
        return self.__unpack_by_format_and_position("B", IP_HEADER_SIZE + 1)

    def get_icmp_header_checksum(self) -> int:
        return self.__unpack_by_format_and_position("H", IP_HEADER_SIZE + 2)

    def get_icmp_identifier(self) -> int:
        return self.__unpack_by_format_and_position("H", IP_HEADER_SIZE + 4)

    def get_icmp_sequence_number(self) -> int:
        return self.__unpack_by_format_and_position("H", IP_HEADER_SIZE + 6)

    def get_datetime_sent(self) -> float:
        start = IP_HEADER_SIZE + ICMP_HEADER_SIZE
        end = start + TIMESTAMP_SIZE
        return struct.unpack("!d", self.__recvPacket[start:end])[0]

    def get_icmp_data(self) -> str:
        start = IP_HEADER_SIZE + ICMP_HEADER_SIZE + TIMESTAMP_SIZE
        return self.__recvPacket[start:].decode("utf-8")

    def is_valid_response(self) -> bool:
        return self.__isValidResponse

    def get_icmp_identifier_is_valid(self) -> bool:
        return self.__IcmpIdentifier_isValid

    def get_icmp_sequence_number_is_valid(self) -> bool:
        return self.__IcmpSequenceNumber_isValid

    def get_icmp_raw_data_is_valid(self) -> bool:
        return self.__IcmpRawData_isValid

    # ############################################################################################################ #
    # Setters 　　　　　　　　　                                                                                      #
    # ############################################################################################################ #
    def set_is_valid_response(self, booleanValue: bool):
        self.__isValidResponse = booleanValue

    def set_icmp_identifier_is_valid(self, booleanValue: bool):
        self.__IcmpIdentifier_isValid = booleanValue

    def set_icmp_sequence_number_is_valid(self, booleanValue: bool):
        self.__IcmpSequenceNumber_isValid = booleanValue

    def set_icmp_raw_data_is_valid(self, booleanValue: bool):
        self.__IcmpRawData_isValid = booleanValue

    # ############################################################################################################ #
    # Private Functions　　　　　　　　　                                                                             #
    # ############################################################################################################ #
    def __unpack_by_format_and_position(self, formatCode: str, basePosition: int) -> int:
        number_of_bytes = struct.calcsize(formatCode)
        return struct.unpack(
            "!" + formatCode,
            self.__recvPacket[basePosition: basePosition + number_of_bytes]
        )[0]

    # ############################################################################################################ #
    # Public Functions    　　　　　　　　　                                                                          #
    # ############################################################################################################ #
    def print_result_to_console(self, ttl: int, time_received: float, addr: tuple, original_packet: 'IcmpPacket'):
        time_sent = self.get_datetime_sent()
        rtt = (time_received - time_sent) * 1000

        print(f"{len(self.__recvPacket[IP_HEADER_SIZE:])} bytes from {addr[0]}: icmp_seq={self.get_icmp_sequence_number()} ttl={self.__recvPacket[8]} time={rtt:.3f} ms")

        # Validate Identifier
        if not self.get_icmp_identifier_is_valid():
            print(
                "ICMP Identifier invalid. Received: ",
                self.get_icmp_identifier(),
                "BUT - expected ",
                original_packet.get_packet_identifier(),
            )

        # Validate Sequence Number
        if not self.get_icmp_sequence_number_is_valid():
            print(
                "ICMP Sequence Number invalid. Received: ",
                self.get_icmp_sequence_number(),
                "BUT - expected ",
                original_packet.get_packet_sequence_number(),
            )

        # Validate Raw Data
        if not self.get_icmp_raw_data_is_valid():
            print(
                "ICMP Raw Data invalid. Received: ",
                self.get_icmp_data(),
                "BUT - expected ",
                original_packet.get_data_raw(),
            )

        # Update RTT records
        self.__statistics.update_rtt(rtt)