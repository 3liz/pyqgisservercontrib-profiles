SHELL:=bash
#
# qgis server makefile
#

BUILDID=$(shell date +"%Y%m%d%H%M")
COMMITID=$(shell git rev-parse --short HEAD)

BUILDDIR=build
DIST=${BUILDDIR}/dist

MANIFEST=build.manifest

PYTHON:=python3

FLAVOR:=ltr

dirs:
	mkdir -p $(DIST)

manifest:
	echo name=$(shell $(PYTHON) setup.py --name) > $(MANIFEST) && \
		echo version=$(shell $(PYTHON) setup.py --version) >> $(MANIFEST) && \
		echo buildid=$(BUILDID)   >> $(MANIFEST) && \
		echo commitid=$(COMMITID) >> $(MANIFEST)

# Build dependencies
wheel-deps: dirs
	pip wheel -w $(DIST) -r requirements.txt

wheel:
	mkdir -p $(DIST)
	$(PYTHON) setup.py bdist_wheel --dist-dir=$(DIST)

deliver:
	twine upload -r storage $(DIST)/*

dist: dirs manifest
	rm -rf *.egg-info
	$(PYTHON) setup.py sdist --dist-dir=$(DIST)

clean:
	rm -rf $(BUILDDIR)

test-%:
	$(MAKE) -C tests/docker $* FLAVOR=$(FLAVOR)


lint:
	@flake8 pyqgisservercontrib

test: lint
	$(MAKE) -C tests/docker test-ows FLAVOR=$(FLAVOR)

test-wps: lint
	$(MAKE) -C tests/docker test-wps FLAVOR=$(FLAVOR)

