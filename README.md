# Profile filter plugin for py-qgis-server

Middleware filter for providings profiles handling in [py-qgis-server](https://github.com/3liz/py-qgis-server)

## Description

The `profiles` extension add new uri locations
associated to profiles that defines access control to the ressources.

### Profiles configuration

Profiles are configured using a YAML file. The  path to this configuration file 
is given by the `QGSRV_SERVER_PROFILES` environment variable or the  `profiles` variable
in the `server` section of the [py-qgis-server](https://github.com/3liz/py-qgis-server) configuration.

Example of profile configuration:

```
profiles:
    - myprofile:
        services:   # Allowed services
            - WMS
            - WFS
            ...
        # Parameter substitution
        # These parameters override those defined
        # In the request
        parameters:
            MAP: ...
            LAYERS: ..
            ...
        # List of allowed referers
        allowed_referers:
            - ...
        # Allowed ip/ip ranges
        allowed_ips:
            - XXX.YYY.WWW.ZZZ/NN
            -
```

Profiles are accessed from the url location: `/ows/p/myprofile/`

#### Services

Define a list of service allowed for this profile. Only request for the service
listed are allowed for this profile.

```
services:
    - WMS
    - WFS
```

#### Parameters

Define a list of query parameters added to the request. If a parameter is already
defined in the original request, it will be replaced.

```
parameters:
    - MAP: mypproject.qgs
    - LAYERS: layer1,layer2
```

#### Allowed referers

Explicit list of referers allowed to send requests with this profile. The filter
looks at the `Referer` header of the request.

```
allowed_referers:
    - http://mydomain.com
```

#### Allowed ips

List allowed ips allowed to send requests with this profile. CIDR ranges are allowed.
IPv4 and IPv6 are supported.

```
allowed_ips:
    - 192.168.1.10
    - 192.168.0.0/16
```

When the  server is accessed from behind a reverse proxy this must be declared with the variable `QGSRV_SERVER_HTTP_PROXY=yes` - see the [py-qgis-server](.https://github.com/3liz/py-qgis-server) for details: IPs are checked against the `X-Forwarded-For` header.

#### WPS Access policy

Note: Only for use with [py-qgis-wps](https://github.com/3liz/py-qgis-wps). It has not effects on py-qgis-server. 

Define access policy for processes in WPS services. There is two directives: 'deny' and 'allow'. 
Each entry define a  list of ar defined as comma separated list of Qgis algorithms identifiers. 
Globbing style wildcards are allowed.

Order of evaluation is allow/deny, if one directive match, the other is not evaluated. If none match
access is granted.

```
accesspolicy:
    deny: all
    allow: 'script:*' 
```

#### Others parameters:

The following extra parameters may be defined in the profile configuration file

```
# Allow a default profile for using with default `/ows/` location 
allow_default_profile: yes

# Enable reloading configuration on config file changes
autoreload: yes

# The default profile
# if 'allow_default_profile' is 'yes' and default profile is not defined, then it allows anything as
# if no profiles is used
default: {}

# Global processes accesspolicyd
# The global access policy is added to the per profile policy
accesspolicy:
    deny: all


# Allow splitting the configuration in multiple files
# Note that auto reloading only apply to the main configuration file
profiles: !include [ profiles/*/*.yml , profiles/*/*/*.yml ]

```

