# Ping

Written in Python using raw sockets, ICMP request, and reply messages.

## ping.py

Ping is a computer network app to test whether a particular host is reachable across an IP network.  
It sends ICMP echo request packets to the target and listens for ICMP echo reply packets.  
In order to keep it simple, this program does not follow the official spec in RFC 1739. 

## Instructions

To run ping.py: `sudo python3 ping.py [option] host`

## Environment

```
$ python3 --version
Python 3.13.0

$ uname
Darwin
```

## Demo




