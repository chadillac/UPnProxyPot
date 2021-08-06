#!/usr/bin/env bash

proxy_ip=$1
proxy_port=$2
domain=$3

curl -kvl -H"Host: $domain" --resolve $domain:$proxy_port:$proxy_ip https://$domain:$proxy_port/
