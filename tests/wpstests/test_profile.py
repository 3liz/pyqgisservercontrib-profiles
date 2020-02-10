"""
    Test profiles
"""
from pyqgiswps.tests import HTTPTestCase
from pyqgiswps.executors.processingexecutor import ProcessingExecutor

class Tests(HTTPTestCase):

    def test_profile_request(self):
        """ Test response from root path
        """
        uri = ('/ows/p/wpsonly/?Request=GetCapabilities&service=WPS')
        rv = self.client.get(uri, path='')
        assert rv.status_code == 200

    def test_profile_return_403(self):
        """ Test unauthorized WPS return a 403 response
        """
        uri = ('/ows/p/nowps/?Request=GetCapabilities&service=WPS')
        rv = self.client.get(uri, path='')
        assert rv.status_code == 403

    def test_ip_ok(self):
        """ Test authorized ip return a 200 response
        """
        uri = '/ows/p/wpsrejectips/?service=WPS&request=GetCapabilities'
        rv = self.client.get(uri,  headers={ 'X-Forwarded-For': '192.168.2.1' }, path='')
        assert rv.status_code == 200

    def test_ip_rejected_return_403(self):
        """ Test unauthorized WPS return a 403 response
        """
        uri = '/ows/p/wpsrejectips/?service=WPS&request=GetCapabilities'
        rv = self.client.get(uri, headers={ 'X-Forwarded-For': '192.168.3.1' }, path='')
        assert rv.status_code == 403

    def test_map_profile(self):
        """ Test map profile 
        """
        uri = ('/ows/p/wpsmap/?service=WPS&request=Execute&Identifier=pyqgiswps_test:testcopylayer&Version=1.0.0'
                               '&DATAINPUTS=INPUT=france_parts%3BOUTPUT=france_parts_2')
        rv = self.client.get(uri, path='')
        assert rv.status_code == 200

    def test_access_policy(self):
        """ Test access policy
        """
        uri = ('/ows/p/withpolicy/?service=WPS&request=GetCapabilities')
        rv = self.client.get(uri, path='')
        assert rv.status_code == 200

        exposed = rv.xpath_text('/wps:Capabilities'
                                  '/wps:ProcessOfferings'
                                  '/wps:Process'
                                  '/ows:Identifier')
        # Check that there is only one exposed pyqgiswps_test
        idents = [x for x in exposed.split() if x.startswith('pyqgiswps_test:')]
        assert idents == ['pyqgiswps_test:testsimplevalue']



