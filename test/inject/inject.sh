#!/usr/bin/env bash

## test injection capabilities with a user supplied SOAP payload

## usage example:  
## ./inject.sh inject.tcp.80.xml

curl -v -H "Content-Type: text/xml" -H "SOAPAction: “urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping”" --data @$1 "$2" 2>&1
