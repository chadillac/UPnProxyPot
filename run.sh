#!/usr/bin/env bash

## setup the firewall before we start the pot... or you'll be a reflected DDoS generator
## which will be bad for everyone... yourself included.
./scripts/firewall.sh

## HACK: there is a memleak somewhere, and we don't actually ever delete proxies
##       so we kill => run => sleep => repeat to keep the service in a fresh and
##       running state, this all handles recovery of crashes, freezes, etc.
##       yes it's hacky... yes it actually kinda works (good enough).
while true; do 
    echo "`date`: killing upnproxy..."
    killall -9 upnproxy
    sleep 5
    echo "`date`: starting upnproxy..."
    ./upnproxy >> upnproxy.log 2>&1 &
    echo "`date`: sleeping for 1 hour..."
    sleep 3600
done
