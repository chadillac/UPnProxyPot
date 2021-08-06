#!/usr/bin/bash

## issue SOAP requests against a UPnProxy to get it's NAT mappings 

url=$1
soap_head='<?xml version="1.0" encoding="utf-8"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:upnp-org:serviceId:WANIPConnection.1#GetGenericPortMappingEntry"><NewPortMappingIndex>'
soap_tail='</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>'

for i in `seq 100`; do
    payload=$soap_head$i$soap_tail
    curl -H 'Content-Type: "text/xml;charset=UTF-8"' -H 'SOAPACTION: "urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"' --data "$payload" "$url"
    echo ""
done

