#!/usr/bin/env bash -x
# -*- coding: UTF-8 -*-

# test 
# ./logoutd.py -D -LP 8888
wget --header="Content-Type: application/json" --post-data='{"user":"my_lacy_child"}' -t 1 -qO -  http://127.0.0.1:8888/edward/api/v1.0/status

