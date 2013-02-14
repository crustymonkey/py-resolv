from distutils.core import setup

setup(name='py-resolv' ,
    version='0.2.0' ,
    author='Jay Deiman' ,
    author_email='admin@splitstreams.com' ,
    url='http://stuffivelearned.org' ,
    description='A synchronous and asynchronous DNS client library' ,
    long_description='Full documentation is available at '
        'http://stuffivelearned.org' ,
    packages=['pyresolv'] ,
    package_dir={'pyresolv': 'pyresolv'} ,
    data_files=[ ('share/pyresolv' , ['examples/async_ex.py' ,
                                      'examples/sync_ex.py']) ] ,
    classifiers=[
        'Development Status :: 2 - Pre-Alpha' ,
        'Intended Audience :: Developers' ,
        'Intended Audience :: Information Technology' ,
        'Intended Audience :: System Administrators' ,
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)' ,
        'Natural Language :: English' ,
        'Operating System :: OS Independent' ,
        'Programming Language :: Python :: 2' ,
        'Topic :: Internet :: Name Service (DNS)' ,
    ]
)
