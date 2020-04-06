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
import functools

from tornado.web import HTTPError, RequestHandler

from yaml.nodes import SequenceNode

from typing import Mapping, TypeVar, Any

from ipaddress import ip_address, ip_network
from glob import glob 
from pathlib import Path

from .watchfiles import watchfiles

LOGGER = logging.getLogger('SRVLOG')

# Define an abstract type for HTTPRequest
HTTPRequest = TypeVar('HTTPRequest')

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
        raise ProfileParseError("Expecting 'list' not %s" % type(s))


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

def output_debug_profile(name, p):
    LOGGER.debug(("===== Checking matching profile <%s>:\n"
                  "* services: %s\n"
                  "* parameters: %s\n"
                  "* allowed ips: %s\n"
                  "* allowed referers: %s\n"
                  "* access policy: %s\n"
                  ), name,
                     p._services,
                     p._parameters,
                     p._allowed_ips,
                     p._allowed_referers,
                     p._accesspolicy
                  )

class _Profile:
    
    def __init__(self, data: Mapping[str,Any], wpspolicy: bool=False) -> None:
        self._services    = data.get('services')
        self._parameters  = data.get('parameters',{})
        self._allowed_ips = [ip_network(ip) for ip in data.get('allowed_ips',[])]
        self._allowed_referers = data.get('allowed_referers')
        self._accesspolicy = data.get('accesspolicy') if wpspolicy else None

        # 'only' directive
        self._mapfilters  = _to_list(data.get('only',{}).get('map',[]))

    def test_services(self, request: HTTPRequest) -> None:
        """ Test allowed services
        """
        if not self._services:
            return
        service = request.arguments.get('SERVICE')
        if service:
            service = service[-1]
            if isinstance(service,bytes):
                service = service.decode()
            if not service in self._services:
                raise ProfileError("Rejected service %s" % service)

    def test_allowed_referers_or_ips(self, request: HTTPRequest, http_proxy: bool) -> None:
        """ Test allowed referers or ips
        """
        if self._allowed_referers:
            referer = request.headers.get('Referer')
            if referer in self._allowed_referers:
                # Pass referer
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

    def test_only( self, request: HTTPRequest ) -> None:
        """ Test 'only' directive
        """
        maps = self._mapfilters
        if not maps:
            return

        test = request.arguments.get('MAP')
        if not test:
            return

        test = test[-1]
        if isinstance(test,bytes):
            test = test.decode()
        test = Path(test)
        if not any( test.match(m) for m in maps ):
            raise ProfileError("Rejected MAP: %s" % test)

    def apply(self, handler: RequestHandler, http_proxy: bool, with_referer:bool=False) -> None:
        """ Apply profiles constraints
        """
        request = handler.request
        request.arguments.update((k,[v.encode()]) for k,v in  self._parameters.items())
        self.test_services(request)
        if with_referer:
            self.test_allowed_referers_or_ips(request, http_proxy)
        else:
            self.test_allowed_ips(request, http_proxy)
        self.test_only(request)
        if self._accesspolicy:
            handler.accesspolicy.add_policy(**_kwargs(self._accesspolicy,'deny','allow'))


class ProfileMngr:
    
    @classmethod
    def initialize( cls, profiles: str, exit_on_error: bool=True, wpspolicy: bool=False ) -> 'ProfileMngr':
        """ Create Profile manager

            param Profiles: path to profile configuration
        """
        try:
            mngr = ProfileMngr(wpspolicy=wpspolicy)
            mngr.load(profiles)
            return mngr
        except Exception:
            LOGGER.error("Failed to load profiles %s: %s")
            if exit_on_error:
                traceback.print_exc()
                sys.exit(1)
            else:
                raise

    def __init__(self, wpspolicy: bool=False) -> None:
        self._autoreload = None
        self._wpspolicy  = wpspolicy

    def load( self, profiles: str) -> None:
        """ Load profile configuration
        """
        wps = self._wpspolicy
        LOGGER.info("Reading profiles %s",profiles)
        with open(profiles,'r') as f:
            config = yaml.load(f, Loader=Loader)
        self._profiles = {}
        self._accesspolicy = config.get('accesspolicy') if wps else None

        allow_default = config.get('allow_default_profile', True)
        if allow_default:
            self._profiles['default'] = _Profile(config.get('default',{}), wpspolicy=wps)
        self._profiles.update( (k,_Profile(v,wpspolicy=wps)) for k,v in config.get('profiles',{}).items() )

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

    def apply_profile( self, name: str, handler: RequestHandler, 
                       http_proxy: bool=False, with_referer: bool=False) -> bool:
        """ Check profile condition
        """
        try:
            # name may be a path like string
            if name: name = name.strip('/')
            profile = self._profiles.get(name or 'default')
            if profile is None:
                raise ProfileError("Unknown profile")
            # Apply global access policy
            if self._accesspolicy: 
                handler.accesspolicy.add_policy(**_kwargs(self._accesspolicy,'deny','allow'))
            # Apply filter
            output_debug_profile(name,profile)
            profile.apply(handler, http_proxy, with_referer=with_referer)
            return True
        except ProfileError as err:
            LOGGER.error("Invalid profile '%s': %s", name or "<default>", err)
                
        return False


def prepare_config( config, prefix ):
    
    try:
        config.add_section('contrib:profiles')
    except:
        pass

    default_ = object()

    def init_( section, option, varname, fallback ):
        value = config.get(section, option, fallback=default_)
        if value is default_:
            varvalue = os.getenv(varname)
            if varvalue is not None:
                config.set(section, option, varvalue)
        return value

    init_('server','profiles',prefix+'_SERVER_PROFILES', None)
    init_('contrib:profiles','with_referer', prefix+'_CONTRIB_PROFILES_WITH_REFERER','no')


def register_filters() -> None:
    """
    """
    from pyqgisserver.filters import blockingfilter
    from pyqgisserver.config import get_config

    config = get_config()
    prepare_config(config, 'QGSRV')

    with_profiles = config.get('server','profiles')
    if with_profiles:
        mngr = ProfileMngr.initialize(with_profiles)

        http_proxy = config.getboolean('server','http_proxy',fallback=False)

        with_referer = config.getboolean('contrib:profiles','with_referer')
        if with_referer:
            LOGGER.info("Enabling referer on profile check")

        @blockingfilter()
        def default_filter( handler ):
            if not mngr.apply_profile('default', handler, http_proxy, with_referer=with_referer):
                raise HTTPError(403,reason="Unauthorized profile")

        @blockingfilter(pri=-1000, uri=r"p/(?P<profile>.*)")
        def profile_filter( handler ):
            # Remove profile from argument list
            profile = handler.path_kwargs.pop('profile')
            if not mngr.apply_profile(profile, handler, http_proxy, with_referer=with_referer):
                raise HTTPError(403,reason="Unauthorized profile")

        return [profile_filter, default_filter]
    
    return []


def register_wpsfilters() -> None:
    """ Register filters for WPS
    """
    from pyqgiswps.filters import blockingfilter
    from pyqgiswps.config import get_config

    config = get_config()
    prepare_config(config, 'QYWPS')

    with_profiles = config.get('server','profiles')
    if with_profiles:
        mngr = ProfileMngr.initialize(with_profiles, wpspolicy=True)
       
        http_proxy = config.getboolean('server','http_proxy',fallback=False)

        with_referer = config.getboolean('contrib:profiles','with_referer')
        if with_referer:
            LOGGER.info("Enabling referer on profile check")

        @blockingfilter()
        def default_filter( handler: RequestHandler ) -> None:
            if not mngr.apply_profile('default', handler, http_proxy, with_referer=with_referer):
                raise HTTPError(403,reason="Unauthorized profile")

        @blockingfilter(pri=-1000, uri=r"p/(?P<profile>.*)")
        def profile_filter( handler: RequestHandler ) -> None:
            # Remove profile from argument list
            profile = handler.path_kwargs.pop('profile')
            if not mngr.apply_profile(profile, handler, http_proxy, with_referer=with_referer):
                raise HTTPError(403,reason="Unauthorized profile")

        return [profile_filter, default_filter]
    
    return []


