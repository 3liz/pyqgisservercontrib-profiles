#!/bin/bash

set -e

echo "-- HOME is $HOME"

VENV_PATH=/opt/local/pyqgisserver

if [ "$(id -u)" == "0" ]; then

PIP="$VENV_PATH/bin/pip"
PIP_INSTALL="$VENV_PATH/bin/pip install -U"

echo "-- Installing required packages..."
$PIP_INSTALL -q pip setuptools
$PIP_INSTALL -q --prefer-binary -r requirements.tests
$PIP_INSTALL -q --prefer-binary -r requirements.txt

$PIP_INSTALL -q -e ./

exec gosu $BECOME_USER "$BASH_SOURCE" "$@"

fi 

export QGIS_DISABLE_MESSAGE_HOOKS=1
export QGIS_NO_OVERRIDE_IMPORT=1

# Disable qDebug stuff that bloats test outputs
export QT_LOGGING_RULES="*.debug=false;*.warning=false"

# Run new tests
cd tests/unittests && $VENV_PATH/bin/pytest -v $@

