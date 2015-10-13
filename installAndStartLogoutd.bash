#!/bin/bash

if [[ $(id -u) != 0 ]]
then
	echo "ERROR: Must run as ROOT or via SUDO!"
	exit
fi

echo "Installing..."
set -x
sed "s|GIT_SRC_HOME|${PWD}|g" me.ellinger.edward.logoutd.plist >/Library/LaunchDaemons/me.ellinger.edward.logoutd.plist
launchctl load -w /Library/LaunchDaemons/me.ellinger.edward.logoutd.plist
set +x

