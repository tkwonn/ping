# Ping

Written in Python using raw sockets, ICMP request, and reply messages.

## ping.py

Ping is a computer network app to test whether a particular host is reachable across an IP network. It sends ICMP echo request packets to the target and listens for ICMP echo reply packets.  
In order to keep it simple, this program does not follow the official spec in RFC 1739. 

## Demo

[![asciicast](https://asciinema.org/a/jl8X363T1zhI2xUc6i9NBKKLS.svg)](https://asciinema.org/a/jl8X363T1zhI2xUc6i9NBKKLS)

## Instructions

To run ping.py: `sudo python3 ping.py [option] host`

### Options

- `-c, --count COUNT`: Number of packets to send
- `-i, --interval INTERVAL`: Wait interval seconds between sending each packet (default is 1 second).
- `-d, --debug`: Enable debug mode for detailed output.

## Features

**Raw Socket Communication**  
Utilizes raw sockets to send and receive ICMP packets, providing low-level network access.

**ICMP Packet Construction**  
Manually constructs ICMP Echo Request packets, including headers and payload.

**Packet Unpacking and Verification**   
Receives ICMP Echo Reply packets, unpacks the headers and payload, and verifies the contents to ensure data integrity.

**Round-Trip Time Calculation**  
Measures the time taken for packets to reach the target and return, providing RTT statistics.


## Environment

```
$ python3 --version
Python 3.13.0

$ uname
Darwin
```





