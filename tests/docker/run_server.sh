#!/bin/bash

set -e

VENV_PATH=/opt/local/pyqgisserver

if [ "$(id -u)" == "0" ]; then

PIP="$VENV_PATH/bin/pip"
PIP_INSTALL="$VENV_PATH/bin/pip install -U"

echo "-- Installing required packages..."
$PIP_INSTALL -q pip setuptools
$PIP_INSTALL -q --prefer-binary -r requirements.txt

$PIP_INSTALL -q -e ./

exec gosu $BECOME_USER "$BASH_SOURCE" "$@"

fi 

export QGIS_DISABLE_MESSAGE_HOOKS=1
export QGIS_NO_OVERRIDE_IMPORT=1

$VENV_PATH/bin/qgisserver -b 0.0.0.0 -p 8080 -c /server.conf



