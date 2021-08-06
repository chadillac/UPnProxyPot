#!/usr/bin/env bash

echo "killing procs..."
ansible -i inventory.yaml all -k -m shell -a "killall screen"
