#!/usr/bin/env bash

## apply aggressive rate limiting to prevent SSDP DDoS abuse of honeypot

iptables --flush 
iptables -A INPUT -p udp --dport 1900 -m limit --limit 3/minute --limit-burst 9 -j ACCEPT
iptables -A INPUT -p udp --dport 1900 -j DROP
iptables -nvL
