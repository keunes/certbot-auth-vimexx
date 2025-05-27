from setuptools import setup, find_packages

setup(
    name='certbot-dns-vimexx',
    version='1.0.0',
    description='Certbot DNS Authenticator for Vimexx. It enables automatic handling of DNS-01 challenges required for the issuing of wildcard SSL certificates via certbot.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=[
        'certbot',
        'requests',
        'zope.interface'
    ],
    entry_points={
        'certbot.plugins': [
            'dns-vimexx = certbot_dns_vimexx.dns_vimexx:DNSVimexxAuthenticator'
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        "Development Status :: 5 - Production/Stable",
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Systems Administration'
    ],
    python_requires='>=3.6',
)