"""
    Test profiles
"""
from pyqgisserver.tests import HTTPTestCase
from urllib.parse import urlparse

ns = { 
    "wms": "http://www.opengis.net/wms",
    "ows": "http://www.opengis.net/ows",
}

xlink = "{http://www.w3.org/1999/xlink}"


class Tests(HTTPTestCase):

    def test_profile_request(self):
        """ Test response from root path
        """
        uri = ('/ows/p/wmsonly/?bbox=-621646.696284,5795001.359349,205707.697759,6354520.406319&crs=EPSG:3857'
               '&dpi=96&exceptions=application/vnd.ogc.se_inimage&format=image/png&height=915'
               '&layers=france_parts&request=GetMap'
               '&service=WMS&transparent=TRUE&version=1.3.0&width=1353')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200

    def test_profile_return_403(self):
        """ Test unauthorized WFS return a 403 response
        """
        uri = ('/ows/p/wmsonly/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 403

    def test_ip_ok(self):
        """ Test authorized ip return a 200 response
        """
        uri = '/ows/p/rejectips/?service=WMS&request=GetCapabilities'
        rv = self.client.get(uri,  headers={ 'X-Forwarded-For': '192.168.2.1' }, path='')
        assert rv.status_code == 200

    def test_ip_rejected_return_403(self):
        """ Test unauthorized WFS return a 403 response
        """
        uri = '/ows/p/rejectips/?service=WMS&request=GetCapabilities'

        rv = self.client.get(uri, headers={ 'X-Forwarded-For': '192.168.3.1' }, path='')
        assert rv.status_code == 403

    def test_profile_with_path(self):
        """ Test response from root path
        """
        uri = ('/ows/p/wms/testpath?bbox=-621646.696284,5795001.359349,205707.697759,6354520.406319&crs=EPSG:3857'
               '&dpi=96&exceptions=application/vnd.ogc.se_inimage&format=image/png&height=915'
               '&layers=france_parts&request=GetMap'
               '&service=WMS&transparent=TRUE&version=1.3.0&width=1353')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200

    def test_wfs_profile(self):
        """ Test profile located in subdir
        """
        uri = ('/ows/p/wfsonly/?service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200
        assert rv.headers['Content-Type'] == 'text/xml; charset=utf-8'
        elem = rv.xml.findall(".//ows:Get", ns)
        assert len(elem) > 0

        urlref = urlparse(uri)

        href = urlparse(elem[0].get(xlink+'href'))
        assert href.path == urlref.path.rstrip('/')


    def test_map_only_ok(self):
        """ Test the 'only' directive
        """
        uri = ('/ows/p/mappolicy?bbox=-621646.696284,5795001.359349,205707.697759,6354520.406319&crs=EPSG:3857'
               '&dpi=96&exceptions=application/vnd.ogc.se_inimage&format=image/png&height=915'
               '&layers=france_parts&request=GetMap'
               '&service=WMS&transparent=TRUE&version=1.3.0&width=1353'
               '&map=france_parts')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200

    def test_map_only_rejected(self):
        """ Test the 'only' directive
        """
        uri = ('/ows/p/mappolicy?bbox=-621646.696284,5795001.359349,205707.697759,6354520.406319&crs=EPSG:3857'
               '&dpi=96&exceptions=application/vnd.ogc.se_inimage&format=image/png&height=915'
               '&layers=france_parts&request=GetMap'
               '&service=WMS&styles=default&transparent=TRUE&version=1.3.0&width=1353'
               '&map=belgium_parts')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 403


    def test_referer_return_403(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'referer_not_ok' })
        assert rv.status_code == 403


    def test_referer_return_ok(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'referer/ok' })
        assert rv.status_code == 200


    def test_referer_wildcard_ok(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'http://referer.com/foobar' })
        assert rv.status_code == 200

    def test_referer_regexp_ok(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'http://regexp/123/ok' })
        assert rv.status_code == 200

    def test_referer_regexp_simple_match(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'http://longpath/with/multiple/steps' })
        assert rv.status_code == 200

    def test_referer_regexp_403(self):
        """ Test referer filter
        """
        uri = ('/ows/p/referer/?exceptions=application/vnd.ogc.se_inimage'
               '&service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='', headers={ 'Referer': 'http://regexp/123a/ok' })
        assert rv.status_code == 403

    def test_wfs3_profile(self):
        """ Test profile located in subdir
        """
        uri = ('/ows/p/wfsonly/wfs3/')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200

    def test_wfs3_profile_rejected(self):
        """ Test wfs3 profile is rejected
        """
        uri = ('/ows/p/wmsonly/wfs3/')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 403

    def test_wms_proxy_url(self):
        """ Test proxy urls definitions
        """
        uri = ('/ows/p/proxyurls/?service=WMS&request=GetCapabilities')
        
        rv = self.client.get(uri,path='')
        assert rv.status_code == 200
        assert rv.headers['Content-Type'] == 'text/xml; charset=utf-8'
        elem = rv.xml.findall(".//wms:OnlineResource", ns)
        assert len(elem) > 0

        urlref = urlparse('https://wms.url/path/')

        href = urlparse(elem[0].get(xlink+'href'))
        assert href.scheme   == urlref.scheme
        assert href.hostname == urlref.hostname
        assert href.path     == urlref.path

    def test_wfs_urls_profile(self):
        """ Test proxy urls definitions
        """
        uri = ('/ows/p/proxyurls/?service=WFS&request=GetCapabilities')

        rv = self.client.get(uri,path='')
        assert rv.status_code == 200
        assert rv.headers['Content-Type'] == 'text/xml; charset=utf-8'
        elem = rv.xml.findall(".//ows:Get", ns)
        assert len(elem) > 0

        urlref = urlparse('https://wfs.url/path/')

        href = urlparse(elem[0].get(xlink+'href'))
        assert href.scheme   == urlref.scheme
        assert href.hostname == urlref.hostname
        assert href.path     == urlref.path

    def test_wfs3_urls_profile(self):
        """ Test proxy urls definitions
        """
        uri = ('/ows/p/proxyurls/wfs3/')
        rv = self.client.get(uri,path='')
        assert rv.status_code == 200
        assert rv.headers['Content-Type'] == 'application/json'

        data = rv.json()
        href = urlparse(data['links'][0]['href'])

        urlref = urlparse('https://wfs.url/path/')
        assert href.scheme   == urlref.scheme
        assert href.hostname == urlref.hostname
        assert href.path.startswith(urlref.path)
