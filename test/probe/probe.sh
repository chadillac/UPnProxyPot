#!/usr/bin/env bash

nc -vvvu $1 1900 < probe.http
