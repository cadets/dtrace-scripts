#!/usr/bin/env bash

RAW_CADETS_TOPIC=cadets-trace
VERSION_FILE="/etc/tc-version"

ETHERFACES=$(ifconfig -l ether)
NETWORK_DETAILS="["

DELIMITER=' '

for face in $ETHERFACES; do
    ETHER=$(ifconfig $face | grep ether | awk '{print $2}')
    INET=$(ifconfig $face | grep '\<inet\>' | awk '{print $2}')
    INET6=$(ifconfig $face | grep '\<inet6\>' | awk '{print $2}')
    NETWORK_DETAILS+=$DELIMITER
    NETWORK_DETAILS+="{\"name\":\""
    NETWORK_DETAILS+=$face
    NETWORK_DETAILS+="\", \"mac\":\""
    NETWORK_DETAILS+=$ETHER
    NETWORK_DETAILS+="\", \"inet\":\""
    NETWORK_DETAILS+=$INET
    NETWORK_DETAILS+="\", \"inet6\":\""
    NETWORK_DETAILS+=$INET6
    NETWORK_DETAILS+="\"}"
    DELIMITER=','
done

NETWORK_DETAILS+="]"

HOSTNAME=$(hostname)
UNAME=$(uname -m -r -s -v)
HOSTUUID=$(sysctl -n kern.hostuuid)

ddtrace_producer -t $RAW_CADETS_TOPIC -s audit.d "$HOSTUUID" "$UNAME" "$HOSTNAME" "$(echo $NETWORK_DETAILS)" "$(cat $VERSION_FILE)"
