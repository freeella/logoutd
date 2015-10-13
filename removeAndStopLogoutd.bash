#!/bin/bash

if [[ $(id -u) != 0 ]]
then
	echo "ERROR: Must run as ROOT or via SUDO!"
	exit
fi

echo "Uninstalling..."
set -x
launchctl unload -w /Library/LaunchDaemons/me.ellinger.edward.logoutd.plist
rm /Library/LaunchDaemons/me.ellinger.edward.logoutd.plist
set +x

