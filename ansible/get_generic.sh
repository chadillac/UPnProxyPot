#!/usr/bin/env bash

## issue a generic command against all upnproxy_pot instances

ansible -i inventory.yaml all -k -m shell -a "$1"
