#!/bin/bash

# Ensure socket dir exists and has correct ownership
mkdir -p /var/run/fcgiwrap
chown www-data:www-data /var/run/fcgiwrap

# Start fcgiwrap as www-data to create the socket with right permissions
spawn-fcgi -u www-data -g www-data -s /var/run/fcgiwrap/fcgiwrap.socket /usr/sbin/fcgiwrap

# TODO: potentially unnecessary, had permissions issues when testing
chmod 766 /var/run/fcgiwrap/fcgiwrap.socket

# Start nginx in foreground
exec nginx -g "daemon off;"

