#!/bin/sh

#Usage: [sudo] rm_route.sh <interface> <from_port> <to_port> <for IP>

RULE_NUM=$(iptables -t nat -v -L PREROUTING -n --line-number | grep ${1} | grep ${4} | grep "dpt:${2} redir ports ${3}" | cut -d' ' -f 1)

if [ ${RULE_NUM} ]; then
    iptables -t nat --delete PREROUTING $RULE_NUM
else
    echo "No rule found!"
fi

