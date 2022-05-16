import os
import sys
import logging
import pytest

from pathlib import Path

from pyqgiswps.tests import TestRuntime


@pytest.fixture(scope='session')
def outputdir(request):
    outdir=request.config.rootdir.join('__outputdir__')
    os.makedirs(outdir.strpath, exist_ok=True)
    return outdir


@pytest.fixture(scope='session')
def data(request):
    return request.config.rootdir.join('data')


def pytest_sessionstart(session):

    rt = TestRuntime.instance()
    rt.start()


def pytest_sessionfinish(session, exitstatus):
    """
    """
    rt = TestRuntime.instance()
    rt.stop()

