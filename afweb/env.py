#!/usr/bin/env python

"""pyairfire.web.env: provides information about about web app environment
"""

__author__      = "Joel Dubowy"

import re
import subprocess

__all__ = [
    'python_version',
    'pyenv_version',
    'pip_packages',
    'config_to_dict',
]

def python_version():
    try:
        return subprocess.Popen(['python', '--version'],
            stderr=subprocess.PIPE).stderr.read()
    except:
        pass


def pyenv_version():
    try:
        return subprocess.Popen(['pyenv', 'version'],
            stdout=subprocess.PIPE).stdout.read()
    except:
        pass

def pip_packages():
    try:
        return [pkg.split('==') for pkg in subprocess.Popen(['pip','freeze'],
            stdout=subprocess.PIPE).stdout.read().split('\n') if pkg]
    except:
        pass

CONFIG_KEY_MATCHER = re.compile('^[A-Z_]+$')
def config_to_dict(config):
    """Returns a dict containing only the attributes of the config
    object/module containing capital letters and underscores in
    their names
    """
    try:
        return {
            k:v for k,v in config.__dict__.items()
                if CONFIG_KEY_MATCHER.match(k)
        }
    except:
        pass
