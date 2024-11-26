class Statistics:
    def __init__(self):
        self.__minRTT = -1
        self.__maxRTT = -1
        self.__numberOfRTTs = 0
        self.__totalRTTtime = 0.0
        self.__packetsSent = 0
        self.__packetErrors = 0

    def increment_packets_sent(self):
        self.__packetsSent += 1

    def increment_packet_errors(self):
        self.__packetErrors += 1

    def update_rtt(self, currentRTT: float):
        """Updates RTT records based on the current RTT."""
        if self.__minRTT == -1:
            self.__minRTT = currentRTT
            self.__maxRTT = currentRTT
        else:
            if currentRTT < self.__minRTT:
                self.__minRTT = currentRTT
            if currentRTT > self.__maxRTT:
                self.__maxRTT = currentRTT

        # Update the totals as well
        self.__totalRTTtime += currentRTT
        self.__numberOfRTTs += 1

    def __get_avg_rtt(self) -> float:
        return self.__totalRTTtime / self.__numberOfRTTs if self.__numberOfRTTs > 0 else 0.0

    def print_statistics(self):
        packetsReceived = self.__packetsSent - self.__packetErrors
        percentLost = (self.__packetErrors / self.__packetsSent) * 100 if self.__packetsSent else 0
        percentSuccess = 100 - percentLost

        print(f"{self.__packetsSent} packets transmitted, {packetsReceived} packets received, {round(percentLost, 2)}% packet loss")
        if self.__numberOfRTTs > 0:
            print(f"round-trip min/avg/max = {round(self.__minRTT, 3)} / {round(self.__get_avg_rtt(), 3)} / {round(self.__maxRTT, 3)} ms")
        else:
            print("No RTT records available.")