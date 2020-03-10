SHELL:=bash
# 
#  Makefile for running server in docker containers
#
COMMITID=$(shell git rev-parse --short HEAD)

FLAVOR:=ltr

REGISTRY_URL ?= 3liz
REGISTRY_PREFIX=$(REGISTRY_URL)/

QGIS_IMAGE=$(REGISTRY_PREFIX)qgis-map-server:$(FLAVOR)

SERVER_HTTP_PORT:=127.0.0.1:8888

BECOME_USER:=$(shell id -u)

ifndef LOCAL_HOME
	LOCAL_HOME=$(shell pwd)
endif

SRCDIR=$(shell realpath ../..)

SCRIPTS=./tests/docker


local:
	rm -rf $$(pwd)/.local
	mkdir -p  $$(pwd)/.local  $(LOCAL_HOME)/.cache


test: local
	echo -n "Restart qgis" > .qgis-restart
	docker run --rm --name qgis-py-server-test-$(COMMITID) -w /src \
		-u $(BECOME_USER) \
		-v $(SRCDIR):/src \
		-v $$(pwd)/.local:/.local \
		-v $(LOCAL_HOME)/.cache:/.cache \
		-e PIP_CACHE_DIR=/.cache \
		-e QGSRV_TEST_PROTOCOL=/src/tests/data \
		-e QGSRV_SERVER_PROFILES=/src/tests/profiles.yml \
		-e QGSRV_SERVER_RESTARTMON=/src/.qgis-restart \
		-e QGSRV_CACHE_ROOTDIR=/src/tests/data \
		-e QGSRV_SERVER_HTTP_PROXY=yes \
		-e QGIS_OPTIONS_PATH=/src/tests/qgis \
		-e QGSRV_LOGGING_LEVEL=DEBUG \
		-e PYTEST_ADDOPTS="$(PYTEST_ADDOPTS)" \
		--entrypoint $(SCRIPTS)/run_tests.sh \
		$(QGIS_IMAGE)


WORKERS:=1

run: local
	echo -n "Restart qgis" > .qgis-restart
	docker run -it --rm -p $(SERVER_HTTP_PORT):8080 --name qgis-py-server-run-$(COMMITID) -w /src \
		-u $(BECOME_USER) \
		-v $(SRCDIR):/src \
		-v $$(pwd)/.local:/.local \
		-v $$(pwd)/server.conf:/server.conf \
		-v $(LOCAL_HOME)/.cache:/.cache \
		-v $(PLUGINPATH):/plugins \
		-e PIP_CACHE_DIR=/.cache \
		-e QGSRV_SERVER_WORKERS=$(WORKERS) \
		-e QGSRV_CACHE_ROOTDIR=/src/tests/data \
		-e QGSRV_TEST_PROTOCOL=/src/tests/data \
		-e QGSRV_SERVER_PROFILES=/src/tests/profiles.yml \
		-e QGSRV_SERVER_RESTARTMON=/src/.qgis-restart \
		-e QGSRV_SERVER_HTTP_PROXY=yes \
		-e QGSRV_LOGGING_LEVEL=DEBUG \
		-e QGSRV_SERVER_PLUGINPATH=/plugins \
		-e PYTHONWARNINGS=d \
		-e QGIS_OPTIONS_PATH=/src/tests/qgis \
		-e QGSRV_DATA_PATH=/.local/share/qgis-server \
		--entrypoint $(SCRIPTS)/run_server.sh \
		$(QGIS_IMAGE)


QGIS_WPSIMAGE=$(REGISTRY_PREFIX)qgis-wps:$(FLAVOR)

wpstest: local
	docker run --rm --name qgis-wps-test-$(FLAVOR)-$(COMMITID) -w /src \
		-u $(BECOME_USER) \
		-v $(SRCDIR):/src \
		-v $$(pwd)/.local:/.local \
		-v $(LOCAL_HOME)/.cache:/.cache \
		-e PIP_CACHE_DIR=/.cache \
		-e QGSWPS_SERVER_PROFILES=/src/tests/profiles.yml \
		-e PYTEST_ADDOPTS="$(PYTEST_ADDOPTS)" \
		-e QGSWPS_CACHE_ROOTDIR=/src/tests/data \
		-e QGSWPS_PROCESSING_PROVIDERS_MODULE_PATH=/src/tests/wpstests \
		-e QGSWPS_SERVER_HTTP_PROXY=yes \
		-e QGIS_OPTIONS_PATH=/src/tests/qgis \
		--entrypoint $(SCRIPTS)/run-wps-tests.sh \
		$(QGIS_WPSIMAGE)

wpsrun: local
	docker run --rm --name qgis-wps-test-$(FLAVOR)-$(COMMITID) -w /src \
		-u $(BECOME_USER) \
		-v $(SRCDIR):/src \
		-v $$(pwd)/.local:/.local \
		-v $(LOCAL_HOME)/.cache:/.cache \
		-e PIP_CACHE_DIR=/.cache \
		-e WORKERS=$(WORKERS) \
		-e QYWPS_SERVER_PROFILES=/src/tests/profiles.yml \
		-e PYTEST_ADDOPTS="$(PYTEST_ADDOPTS)" \
		-e QGSWPS_CACHE_ROOTDIR=/src/tests/data \
		-e QGSWPS_PROCESSING_PROVIDERS_MODULE_PATH=/src/tests/wpstests \
		-e QGSWPS_SERVER_HTTP_PROXY=yes \
		-e QGIS_OPTIONS_PATH=/src/tests/qgis \
		-e QGSWPS_LOGLEVEL=DEBUG \
		--entrypoint $(SCRIPTS)/run-wps-server.sh \
		$(QGIS_WPSIMAGE)


