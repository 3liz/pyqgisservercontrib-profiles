"""
    Test profiles
"""
from pyqgiswps.app import WPSProcess, Service
from pyqgiswps.tests import HTTPTestCase

class Tests(HTTPTestCase):

    def test_profile_request(self):
        """ Test response from root path
        """
        uri = ('/ows/p/wpsonly/?Request=GetCapabilities&service=WPS')
        client = self.client_for(Service())
        rv = client.get(uri, path='')
        assert rv.status_code == 200

    def test_profile_return_403(self):
        """ Test unauthorized WPS return a 403 response
        """
        uri = ('/ows/p/nowps/?Request=GetCapabilities&service=WPS')
        client = self.client_for(Service())
        rv = client.get(uri, path='')
        assert rv.status_code == 403

    def test_ip_ok(self):
        """ Test authorized ip return a 200 response
        """
        uri = '/ows/p/wpsrejectips/?service=WPS&request=GetCapabilities'
        client = self.client_for(Service())
        rv = client.get(uri,  headers={ 'X-Forwarded-For': '192.168.2.1' }, path='')
        assert rv.status_code == 200

    def test_ip_rejected_return_403(self):
        """ Test unauthorized WPS return a 403 response
        """
        uri = '/ows/p/wpsrejectips/?service=WPS&request=GetCapabilities'
        client = self.client_for(Service())
        rv = client.get(uri, headers={ 'X-Forwarded-For': '192.168.3.1' }, path='')
        assert rv.status_code == 403

