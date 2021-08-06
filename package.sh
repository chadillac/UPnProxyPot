#!/usr/bin/env bash

## simple script to build the binary and package up all the bits and pieces needed for distribution

go build upnproxy.go
rm -rf pcaps/*.pcap keys/*.crt
tar cvzf upnproxy.tar.gz payloads/* pcaps/* scripts/* keys/* run.sh upnproxy.go go.mod go.sum
