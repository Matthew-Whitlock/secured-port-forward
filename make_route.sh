#!/bin/sh

#Usage: [sudo] make_route.sh <interface> <from_port> <to_port> <for IP>

iptables -t nat -I PREROUTING -i ${1} -p tcp -s ${4} --dport ${2} -j REDIRECT --to-port ${3} 
