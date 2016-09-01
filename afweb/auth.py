#!/usr/bin/env python

"""auth.py: Provides authentication decorators for web request handlers."""

__author__      = "Joel Dubowy"

import datetime
import hashlib
import os
import time
from functools import wraps

__all__ = [
    'authenticate',
    'basic_auth'
]


class authenticate(object):

    REQUIRED_REQUEST_PARAMS = {
        'timestamp': '_ts',
        'api_key': '_k',
        'signature': '_s'
    }
    REQUIRED_REQUEST_PARAMS_SET = set(REQUIRED_REQUEST_PARAMS.values())
    DEFAULT_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"

    def __init__(self, enabled, api_clients, request_args_getter, request_path_getter,
            request_aborter, timestamp_format=None):
        """Initializer

        Arguments:
        api_clients -- dictionary contain
        request_args_getter -- a function that returns the request args
            dictionary
        request_path_getter -- a function that returns the request path
            dictionary
        request_aborter -- a function that aborts the request; takes two
            optional arguments - http status (which should defaults to 401)
            and message (which should default to authorized)
        """
        self.enabled = enabled
        self.api_clients = api_clients
        self.request_args_getter = request_args_getter
        self.request_path_getter = request_path_getter
        self.request_aborter = request_aborter
        self.timestamp_format = timestamp_format or self.DEFAULT_TIMESTAMP_FORMAT

    def __call__(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if self.enabled:
                self._check_for_auth_params()
                self._check_recency()
                secret = self._look_up_secret()
                signature = self._get_request_signature()
                computed_signature = self._compute_signature(secret)

                if signature != computed_signature:
                    self.request_aborter(401, message="Invalid signature.")

            return f(*args, **kwargs)

        return decorated

    def _check_for_auth_params(self):
        if not self.REQUIRED_REQUEST_PARAMS_SET.issubset(list(self.request_args_getter().keys())):
            message = "Request must include parameters '%s' for authentication" % (
                "', '".join(self.REQUIRED_REQUEST_PARAMS_SET))
            self.request_aborter(401, message=message)



    RECENCY_THRESHOLD = datetime.timedelta(minutes=10)

    def _check_recency(self):
        ts_str = self.request_args_getter()[self.REQUIRED_REQUEST_PARAMS['timestamp']]
        ts = datetime.datetime.strptime(ts_str, self.timestamp_format)
        # Note: Using time.time() to get current time instead of
        # datetime.datetime.utcnow() to enable use of timecop in tests
        now = datetime.datetime.fromtimestamp(time.time())
        if abs(ts - now) > self.RECENCY_THRESHOLD:
            self.request_aborter(401, message="Timestamp is not recent")

    def _look_up_secret(self):
        api_key = self.request_args_getter()[self.REQUIRED_REQUEST_PARAMS['api_key']]
        if api_key not in self.api_clients:
            self.request_aborter(401, message='API key does not exist')

        return self.api_clients[api_key]


    def _get_request_signature(self):
        return self.request_args_getter()[self.REQUIRED_REQUEST_PARAMS['signature']]

    QUERY_SIG_EXCLUDES = ['_s']
    def _compute_signature(self, secret):
        # TODO: urlencode or deencode...need to sign same thing client signs
        str_to_hash = self.request_path_getter()
        str_to_hash += '&'.join(sorted([
            "%s=%s"%(k,v) for (k,v) in self.request_args_getter().items() if k not in self.QUERY_SIG_EXCLUDES
        ]))
        str_to_hash = secret.encode() + str_to_hash.encode()
        return hashlib.sha256(str_to_hash).hexdigest()



class basic_auth(object):

    def __init__(self, enabled, username, password,
            request_authorization_getter, response_class):
        """Initializer

        Arguments:
        username -- basic auth username
        password -- basic auth password
        request_authorization_getter -- a function that returns the request
            args dictionary
        request_path_getter -- a function that returns the request path
            dictionary
        request_aborter -- a function that aborts the request; takes two
            optional arguments - http status (which should defaults to 401)
            and message (which should default to authorized)
        """
        self.enabled = enabled
        self.username = username # TODO: set to "" if None ?
        self.password = password # TODO: set to "" if None ?
        self.request_authorization_getter = request_authorization_getter
        self.response_class = response_class

    def __call__(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if self.enabled:
                auth = self.request_authorization_getter()
                if not auth or not self._check_auth(auth.username, auth.password):
                    return self._authenticate()
            return f(*args, **kwargs)
        return decorated

    def _check_auth(self, username, password):
        """This function is called to check if a username /
        password combination is valid.
        """
        return username == self.username and password == self.password

    def _authenticate(self):
        """Sends a 401 response that enables basic auth"""
        return self.response_class(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

