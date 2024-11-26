import argparse
import os
import sys
import signal
import time
from socket import gethostbyname, gaierror
from icmp_packet import IcmpPacket
from statistics import Statistics
from constants import RAW_DATA, ICMP_HEADER_SIZE

class Ping:
    def __init__(self, target_host: str, count: int = None, wait: int = 1, debug: bool = False):
        self.__target_host = target_host
        self.__count = count
        self.__wait = wait
        self.__debug = debug
        self.__statistics = Statistics()
        self.__running = True
        signal.signal(signal.SIGINT, self.__signal_handler)

    def __signal_handler(self, signum, frame):
        self.__running = False

    def send_ping(self):
        try:
            i = 0
            target_ip = gethostbyname(self.__target_host)
            print(f"\nPING {self.__target_host} ({target_ip}): {ICMP_HEADER_SIZE + len(RAW_DATA)} data bytes")

            while self.__running:
                if self.__count is not None and i >= self.__count:
                    break
                # Create new IcmpPacket instance for each probe to avoid stale internal state
                # Since a new socket is created for each send/receive operation, 
                # there's no benefit in reusing the IcmpPacket instance
                icmp_packet = IcmpPacket(self.__statistics, self.__debug)
                identifier = os.getpid() & 0xFFFF
                sequence_number = i
                icmp_packet.build_echo_request_packet(identifier, sequence_number)
                icmp_packet.set_icmp_target(self.__target_host)
                icmp_packet.send_echo_request()

                if self.__debug:
                    icmp_packet.print_icmp_packet_hex()

                time.sleep(self.__wait)
                i += 1

        except KeyboardInterrupt:
            pass
        except gaierror:
            print(f" [ping] Unknown host {self.__target_host}. Exiting...")
            sys.exit(1)
        finally:
            print()
            print(f"--- {self.__target_host} ping statistics ---")
            self.__statistics.print_statistics()
            sys.exit(0)

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "host", type=str, help="Target host to ping."
    )
    parser.add_argument(
        "-c", "--count", type=int, default=None, help="Number of ping requests to send."
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=1, help="Time interval in seconds between each ping request (default: 1)."
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug mode for detailed output."
    )
    return parser

def ping(target_host: str, count: int = None, wait: int = 1, debug: bool = False):
    ping = Ping(target_host, count, wait, debug)
    ping.send_ping()

if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    ping(args.host, args.count, args.interval, args.debug)