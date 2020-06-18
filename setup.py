from setuptools import setup, find_namespace_packages, Extension
import os

def parse_requirements( filename ):
    with open( filename ) as fp:
        return list(filter(None, (r.strip('\n ').partition('#')[0] for r in fp.readlines())))

VERSION = "1.2.0"
DESCRIPTION = "Qgis server profile filters"

kwargs = {}

with open('README.md') as f:
    kwargs['long_description'] = f.read()

# Parse requirement file and transform it to setuptools requirements'''
requirements = 'requirements.txt'
if os.path.exists(requirements):
    kwargs['install_requires']=parse_requirements(requirements)

setup(
    name='pyqgiservercontrib-profiles',
    version=VERSION,
    author='3Liz',
    author_email='infos@3liz.org',
    maintainer='David Marteau',
    maintainer_email='dmarteau@3liz.org',
    description=DESCRIPTION,
    url='https://github.com/pyqgiservercontrib-profiles',
    python_requires=">=3.5",
    packages=find_namespace_packages(include=['pyqgisservercontrib.*']),
    entry_points={
        'qgssrv_contrib_access_policy': [
            'profile-policy = pyqgisservercontrib.profiles.filters:register_policy',
        ]
    },
    namespace_packages=['pyqgisservercontrib'],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    **kwargs
)

