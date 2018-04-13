from setuptools import setup, find_packages

from afweb import __version__

setup(
    name='afweb',
    version=__version__,
    license='GPLv3+',
    author='Joel Dubowy',
    author_email='jdubowy@gmail.com',
    packages=find_packages(),
    scripts=[
        'bin/sign-request'
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3.5",
        "Operating System :: POSIX",
        "Operating System :: MacOS"
    ],
    url='https://github.com/pnwairfire/afweb',
    description='Utilities for web applications',
    install_requires=[
        "afscripting==1.*",
        'tornado==4.3',
        'Flask==0.10.1',
        'Flask-RESTful==0.2.12'
    ],
    dependency_links=[
        "https://pypi.airfire.org/simple/afscripting/"
    ]
)
