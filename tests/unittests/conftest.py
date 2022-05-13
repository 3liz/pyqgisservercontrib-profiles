import sys
import os
import pytest

import logging
from pyqgisserver.tests import TestRuntime
from time import sleep


def pytest_sessionstart(session):
    """ Start subprocesses
    """
    rt = TestRuntime.instance()
    rt.start()
    print("Waiting for server to initialize...")
    sleep(2)

def pytest_sessionfinish(session, exitstatus):
    """ End subprocesses
    """
    rt = TestRuntime.instance()
    rt.stop()
   

