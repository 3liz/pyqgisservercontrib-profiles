""" Read profile data

profiles:
    myprofile:
        # Allowed services
        services:
            - WMS
            - WFS
            ...
        # Override parameters
        parameters:
            MAP: ....
            ....
        # List of  allowed referers:
        # Need (contrib:profiles -> referer_filter)
        allowed_referers:
            - ...
        # List of allowed ips range
        allowed_ips:
            - 192.168.0.3/16
            - ...

    # Other profiles follows
"""
import os
import sys
import logging
import yaml
import traceback
import jsonschema
import re

from tornado.web import HTTPError

from yaml.nodes import SequenceNode

from typing import Mapping, TypeVar, Any, Optional, Dict, List

from ipaddress import ip_address, ip_network
from glob import glob 
from pathlib import Path

from pyqgisservercontrib.core.watchfiles import watchfiles
from pyqgisservercontrib.core.filters import policy_filter

LOGGER = logging.getLogger('SRVLOG.profiles')

# Define an abstract type for HTTPRequest
HTTPRequest = TypeVar('HTTPRequest')

#
# Schema for profiles
#

SERVICE_SCHEMA = dict(
    type='array',
    items={ 'type':'string' },
    uniqueItems=True
)

PARAMETERS_SCHEMA = dict(
    type='object',
    properties={ 'additionalProperties': { 'type': 'string' }}
)

REFERER_SCHEMA = dict(
    type='array',
    items={ 'type':'string' }
)

IPS_SCHEMA = dict(
    type='array',
    items={ 'type':'string' }
)

POLICY_SCHEMA = dict(
    type='object',
    properties={
        'deny': { 'oneOf': [
            { 'type':'string'},
            { 'type':'array', 'items':{ 'type':'string' }}
        ]},
        'allow':  { 'oneOf': [
            { 'type':'string'},
            { 'type':'array', 'items':{ 'type':'string' }}
        ]},
    }
)


URL_SCHEMA = dict(
    type = 'object',
    properties={ 'additionalProperties': { 'oneOf': [
        { 'type': 'string' },
        dict(
            type='object',
            properties={
                'url': { 'type':'string' },
                'serviceURL': { "type": "boolean" },
            },
            required=["url"],
        ),
    ]}}
)


PROFILE_SCHEMA = dict(
    type = 'object',
    properties = dict(
        service = SERVICE_SCHEMA,
        parameters = PARAMETERS_SCHEMA,
        allowed_referers = REFERER_SCHEMA,
        allowed_ips = IPS_SCHEMA,
        accesspolicy = POLICY_SCHEMA,
        urls = URL_SCHEMA,
    )
)

SCHEMA= dict(
    type = 'object',
    properties=dict(
        autoreload = { 'type': 'boolean' },
        allow_default_profile = { 'type': 'boolean' },
        accesspolicy = POLICY_SCHEMA,
        default  = PROFILE_SCHEMA,
        profiles = { 'type': 'object', "properties": {
            'additionalProperties': PROFILE_SCHEMA
        }}
    )  
)


class ProfileParseError(Exception):
    pass


def _to_list( arg ):
    """ Convert an argument to list
    """
    if isinstance(arg,list):
        return arg
    elif isinstance(arg,str):
        return arg.split(',')
    else:
        raise ProfileParseError("Expecting 'list' not %s" % type(arg))


class Loader(yaml.SafeLoader):
    """ See https://pyyaml.org/wiki/PyYAMLDocumentation
    """  

    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]
        super(Loader, self).__init__(stream)

    def include(self, node):
        """
        """
        if isinstance(node, SequenceNode):
            filelist = self.construct_sequence(node)
        else:
            filelist = [ self.construct_scalar(node) ]
        value = {}
        for fileglob in filelist:
            if not os.path.isabs(fileglob):
                fileglob = os.path.join(self._root, fileglob)
            for filename in glob(fileglob):
                try:
                    with open(filename, 'r') as f:
                        data = yaml.load(f, Loader)
                        if not isinstance(data, dict):
                            raise Exception("Expecting 'dict', not %s" % type(data))
                        value.update(data)
                        LOGGER.debug("Loaded profile: %s", filename)
                except Exception as err:
                    LOGGER.error("Failed to load %s: %s", filename, err)
                    raise

        return value


Loader.add_constructor('!include', Loader.include)


def _kwargs( kwargs, *args ):
    return { k:kwargs.get(k) for k in args }


class ProfileError(Exception):
    """ Raised when profil does not match
    """

def output_debug_profile(name, p, endpoint):
    import json
    LOGGER.debug((f"===== Checking matching profile <{name}>:\n"
                  f"* services: {p._services}\n"
                  f"* parameters: {p._parameters}\n"
                  f"* allowed ips: {p._allowed_ips}\n"
                  f"* allowed referers: {p._allowed_referers}\n"
                  f"* access policy: {p._accesspolicy}\n"
                  f"* proxy urls: {json.dumps(p._urls, indent=2)}\n"
                  f"* endpoint: {endpoint}\n"
                  )),

REGEXP_PREFIX="@RE:"
def _match_fun(e):
    if e.startswith(REGEXP_PREFIX):
        p = re.compile(e[len(REGEXP_PREFIX):])
        return lambda r: p.match(r)
    else:
        return lambda r: Path(r).match(e)


class _Profile:
    
    def __init__(self, name: str, data: Mapping[str,Any], wpspolicy: bool=False) -> None:
        self._name        = name
        self._services    = data.get('services')
        self._parameters  = data.get('parameters',{})
        self._allowed_ips = [ip_network(ip) for ip in data.get('allowed_ips',[])]
        self._accesspolicy = data.get('accesspolicy') if wpspolicy else None

        self._arguments = {}

        # Urls have two different forms, use one
        def _url2dict( item ):
            if isinstance(item, str):
                item={ 'url': item, 'serviceURL': True } 
            return item

        self._urls = { k: _url2dict(v) for k,v in data.get('urls',{}).items() }

        self._allowed_referers = [_match_fun(r) for r in  data.get('allowed_referers',[])]

        # 'only' directive
        self._mapfilters  = _to_list(data.get('only',{}).get('map',[]))

    def get_service(self, endpoint: Optional[str] = None) -> str:
        """ Return  request service
        """
        service = self._arguments.get('SERVICE')
        if service:
            service = service[-1]
            if isinstance(service,bytes):
                service = service.decode()
        else: 
            # Check wfs3 service
            if endpoint and endpoint.startswith('/wfs3'):
                service = 'WFS'

        return service

    def test_services(self, request: HTTPRequest, service: str) -> None:
        """ Test allowed services
        """
        if not self._services:
            return

        if self._services and service and service not in self._services:
            raise ProfileError("Rejected service %s" % service)

    def test_allowed_referers_or_ips(self, request: HTTPRequest, http_proxy: bool) -> None:
        """ Test allowed referers or ips
        """
        if self._allowed_referers:
            referer = request.headers.get('Referer')
            if referer and any( m(referer) for m in self._allowed_referers ):
                return
            elif len(self._allowed_ips) == 0:
                # No ips to check: return failure
                raise ProfileError("Rejected referer: %s" % referer)

        # Check ips
        self.test_allowed_ips(request, http_proxy)

    def test_allowed_ips(self, request: HTTPRequest, http_proxy: bool) -> None:
        """ Test allowed ips

            If behind a proxy we use the X-Forwarded-For header to check ip
        """
        if len(self._allowed_ips) == 0:
            return

        if http_proxy:
            ip = request.headers.get('X-Forwarded-For')
            if not ip:
                raise ProfileError("Missing or empty 'X-Forwarded-For' header")
        else:
            ip = request.remote_ip
        
        ip = ip_address(ip)
        if not any( (ip in _ips) for _ips in self._allowed_ips ):
            raise ProfileError("Rejected ip %s" % ip)

    def test_only(self) -> None:
        """ Test 'only' directive
        """
        maps = self._mapfilters
        if not maps:
            return

        test = self._arguments.get('MAP')
        if not test:
            return

        test = test[-1]
        if isinstance(test,bytes):
            test = test.decode()
        test = Path(test)
        if not any( test.match(m) for m in maps ):
            raise ProfileError("Rejected MAP: %s" % test)

    def test_urls( self, request: HTTPRequest, service: str, endpoint: str ) -> None:
        """ Override 'X-Forwarded-Url' header
        """
        # Retrieve url associated to the service
        # and override the 'X-Forwarded-Url' header
        url = self._urls.get(service)
        if url:
            request.headers['X-Forwarded-Url'] = f"{url['url'].strip('/')}{endpoint}"
            # Supported in Qgis 3.20+, replace the complete url (query params included...)
            # As 3.20.3 does not work with WFS3
            if url['serviceURL']:
                request.headers['X-Qgis-Service-Url'] = url['url']
        # Do not change url for default profile
        elif self._name != 'default':
            request.headers['X-Forwarded-Url'] = f"{request.protocol}://{request.host}/ows/p/{self._name}{endpoint}"

    def apply(self, request: HTTPRequest, endpoint: str, http_proxy: bool, with_referer: bool=False) -> Optional[Dict]:
        """ Apply profiles constraints
        """
        request.arguments.update((k,[v.encode()]) for k,v in  self._parameters.items())
       
        self._arguments = {k.upper(): v for k, v in request.arguments.items()} 

        service = self.get_service(endpoint)
        self.test_services(request, service)
        self.test_urls(request, service, endpoint)
        if with_referer:
            self.test_allowed_referers_or_ips(request, http_proxy)
        else:
            self.test_allowed_ips(request, http_proxy)
        self.test_only()
        if self._accesspolicy:
            return _kwargs(self._accesspolicy,'deny','allow')


class ProfileMngr:
    
    @classmethod
    def initialize( cls, profiles: str, exit_on_error: bool=True, wpspolicy: bool=False,
                    with_referer: bool=False,
                    http_proxy: bool=False) -> 'ProfileMngr':
        """ Create Profile manager

            param Profiles: path to profile configuration
        """
        try:
            mngr = ProfileMngr(wpspolicy=wpspolicy, with_referer=with_referer,
                               http_proxy=http_proxy)
            mngr.load(profiles)
            return mngr
        except Exception:
            LOGGER.error("Failed to load profiles %s", profiles)
            if exit_on_error:
                traceback.print_exc()
                sys.exit(1)
            else:
                raise

    def __init__(self, wpspolicy: bool=False, with_referer: bool=False,
                 http_proxy: bool=False ) -> None:
        self._autoreload = None
        self._wpspolicy  = wpspolicy
        self._with_referer = with_referer
        self._http_proxy = http_proxy

    def load( self, profiles: str) -> None:
        """ Load profile configuration
        """
        wps = self._wpspolicy
        LOGGER.info("Reading profiles %s (wps policy: %s)",profiles, wps)
        with open(profiles,'r') as f:
            config = yaml.load(f, Loader=Loader)
            # Validate configuration
            try:
                jsonschema.validate(config, SCHEMA)
            except jsonschema.exceptions.ValidationError:
                LOGGER.critical("Profile syntax error")
                raise
        self._profiles = {}
        self._accesspolicy = config.get('accesspolicy') if wps else None

        allow_default = config.get('allow_default_profile', True)
        if allow_default:
            self._profiles['default'] = _Profile('default',config.get('default',{}), wpspolicy=wps)
        self._profiles.update( (k,_Profile(k,v,wpspolicy=wps)) for k,v in config.get('profiles',{}).items() )

        # Configure auto reload
        if config.get('autoreload', False):
            if self._autoreload is None:
                check_time = config.get('autoreload_check_time', 3000)
                self._autoreload = watchfiles([profiles], 
                                              lambda modified_files: self.load(profiles), 
                                              check_time=check_time)
            if not self._autoreload.is_running():
                LOGGER.info("Enabling profiles autoreload")
                self._autoreload.start()
        elif self._autoreload is not None and self._autoreload.is_running():
            LOGGER.info("Disabling profiles autoreload")
            self._autoreload.stop()            

    def apply_profile( self, name: str, endpoint: str, request: HTTPRequest, 
                       wps_policies: Optional[List]=None) -> bool:
        """ Check profile condition
        """
        try:
            # name may be a path like string
            if name: 
                name = name.strip('/')
            profile = self._profiles.get(name or 'default')
            if profile is None:
                raise ProfileError("Unknown profile")
            # Apply global access policy
            if self._accesspolicy: 
                wps_policies.append(_kwargs(self._accesspolicy, 'deny', 'allow'))
            # Apply filter
            output_debug_profile(name, profile, endpoint)
            wps_policy = profile.apply(request, endpoint, self._http_proxy, 
                                       with_referer=self._with_referer)
            if wps_policy:
                wps_policies.append(wps_policy)

            return True
        except ProfileError as err:
            LOGGER.error("Invalid profile '%s': %s", name or "<default>", err)
                
        return False


def initialize_profiles(wpspolicy: bool) -> ProfileMngr:
    from  pyqgisservercontrib.core import componentmanager
    configservice  = componentmanager.get_service('@3liz.org/config-service;1')
  
    configservice.add_section('contrib:profiles')

    with_profiles = \
        configservice.get('server','profiles', fallback=None) or \
        configservice.get('contrib:profiles' , 'config', fallback=None)

    if with_profiles:
        http_proxy = configservice.getboolean('server', 'http_proxy', False)

        with_referer = configservice.getboolean('contrib:profiles','with_referer',fallback=False)
        with_referer = configservice.getboolean('contrib:profiles','with_referer',fallback=False)

        mngr = ProfileMngr.initialize(with_profiles, 
                                      wpspolicy=wpspolicy, 
                                      with_referer=with_referer,
                                      http_proxy=http_proxy)

        return mngr
                
    return None


def register_policy(policy_service, *args, **kwargs) -> None:
    """ Register filters
    """
    mngr = initialize_profiles(wpspolicy=False)
    if not mngr:
        return
    
    @policy_filter()
    def default_filter(request: HTTPRequest) -> None:
        if not mngr.apply_profile('default', "/", request):
            raise HTTPError(403,reason="Unauthorized profile")

    @policy_filter(match=r"/ows/p/(?P<profile>(?:(?!/wfs3/?).)*)(?P<endpoint>/.*)?", repl=r"/ows\2")
    def profile_filter(request: HTTPRequest, profile: str, endpoint: Optional[str]=None ) -> List[Dict]:
        if not mngr.apply_profile(profile, endpoint or "/", request):
            raise HTTPError(403,reason="Unauthorized profile")

    policy_service.add_filters([profile_filter, default_filter], pri=1000)


def register_wps_policy(policy_service, *args, **kwargs) -> None:
    """ Entry for WPS service
    """
    mngr = initialize_profiles(wpspolicy=True)
    if not mngr:
        return
 
    @policy_filter()
    def default_filter(request: HTTPRequest) -> List[Dict]:
        wps_policies = []
        if not mngr.apply_profile('default', "/", request, wps_policies=wps_policies):
            raise HTTPError(403,reason="Unauthorized profile")
        return wps_policies 

    @policy_filter(match=r"/store/([^/]+)/(.+)", repl=r"/jobs/\1/files/\2")
    def store_filter(request: HTTPRequest, uuid: str, resource: str) -> List[Dict]:
        return []

    @policy_filter(match=r"/ows/p/(?P<profile>.*)", repl=r"/ows/")
    def profile_filter(request: HTTPRequest, profile: str) -> List[Dict]:
        wps_policies = []
        if not mngr.apply_profile(profile, "/", request, wps_policies=wps_policies):
            raise HTTPError(403,reason="Unauthorized profile")
        return wps_policies 

    policy_service.add_filters([profile_filter, store_filter, default_filter], pri=1000)



