#!/usr/bin/env bash

## generate the master.key that we'll use for cloning certs

key_path=../keys
openssl genrsa -out $key_path/master.key 2048

echo -ne "\n\nmaster key written to $key_path\n\n"
