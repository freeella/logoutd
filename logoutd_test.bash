#!/usr/bin/env bash -x
# -*- coding: UTF-8 -*-

# How to lock screen and avoid relogin?
# Change shell to /usr/bin/false 
# chpass -s /usr/bin/false <username>
# Start login dialogue
# /System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend

# Unlock:
# chpass -s /bin/bash <username>
# Refresh login screen list

# test 
# ./logoutd.py -D -LP 8888
wget --header="Content-Type: application/json" --post-data='{"user":"my_lazy_child"}' -t 1 -qO -  http://127.0.0.1:8888/edward/api/v1.0/status

