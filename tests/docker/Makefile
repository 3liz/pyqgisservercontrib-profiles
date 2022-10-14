SHELL:=bash
.ONESHELL:
.PHONY: env

# 
#  Makefile for running server in docker containers
#

FLAVOR:=ltr

REGISTRY_URL ?= 3liz
REGISTRY_PREFIX=$(REGISTRY_URL)/

QGIS_IMAGE:=$(REGISTRY_PREFIX)qgis-platform:$(FLAVOR)

SERVER_HTTP_PORT:=127.0.0.1:8888
SERVER_MANAGMENT_PORT:=127.0.0.1:19876

BECOME_USER:=$(shell id -u):$(shell id -g)

SRCDIR=$(shell realpath ../..)

PLUGINPATH:=$(SRCDIR)/tests/plugins

SCRIPTS=./tests/docker

local:
	mkdir -p $$(pwd)/.local  $$(pwd)/.cache $$(pwd)/.workdir

_clean:
	rm -rf $$(pwd)/.local $$(pwd)/.cache $$(pwd)/.workdir

clean: _clean env

WORKERS:=1
PROJECTPATH:=$(SRCDIR)/tests/data


env: local
	@echo "Creating environment file for docker-compose"
	@cat <<-EOF > .env
		SRCDIR=$(SRCDIR)
		WORKERS=$(WORKERS)
		BECOME_USER=$(BECOME_USER)
		QGIS_IMAGE=$(QGIS_IMAGE)
		USER=$(USER)
		PWD=$(shell pwd)
		PLUGINPATH=$(PLUGINPATH)
		PROJECTPATH=$(PROJECTPATH)
		SERVER_HTTP_PORT=$(SERVER_HTTP_PORT)
		MANAGEMENT_HTTP_PORT=$(MANAGEMENT_HTTP_PORT)
		PYTEST_ADDOPTS=$(PYTEST_ADDOPTS)
		COMPOSE_PROJECT_NAME=test-pyqgisserver-profile
		EOF


%-up: env
	docker compose \
	-f docker-compose.$*.yml up -V --quiet-pull --remove-orphans \
		--force-recreate --exit-code-from qgis-server

stop:
	docker compose down -v --remove-orphans

test-ows: export RUN_COMMAND=$(SCRIPTS)/run-ows-tests.sh
test-ows: ows-up

test-wps: export RUN_COMMAND=$(SCRIPTS)/run-wps-tests.sh
test-wps: wps-up

run-ows: export RUN_COMMAND=$(SCRIPTS)/run-ows-server.sh
run-ows: ows-up

run-wps: export RUN_COMMAND=$(SCRIPTS)/run-wps-server.sh
run-wps: wps-up


