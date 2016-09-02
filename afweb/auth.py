#!/usr/bin/env python

"""auth.py: Provides authentication decorators for web request handlers."""

__author__      = "Joel Dubowy"

import datetime
import hashlib
import os
import time
import types
import urllib.parse
from functools import wraps

import tornado.log
import tornado.web

__all__ = [
    'TornadoWebRequestAuthMetaClass',
    'authenticate',
    'basic_auth'
]

REQUIRED_REQUEST_PARAMS = {
    'timestamp': '_ts',
    'api_key': '_k',
    'signature': '_s'
}
REQUIRED_REQUEST_PARAMS_SET = set(REQUIRED_REQUEST_PARAMS.values())
TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"

def sign_url(url, key, secret):
    # TODO: if url doesn't have 'http[s://', add it (otherwise
    #   urllib.parse.urlparse returns unexpected parts)
    url_parts = urllib.parse.urlparse(url)

    query_params = []
    if url_parts.query:
        # Note: this preserves multiple occurents of any fields.
        #  e.g. 'a=1&b=s$a=2' -> [['a','1'],['b'.'s'],['a','2']]
        query_params = [e.split('=') for e in url_parts.query.split('&')]

        # don't allow _ts, _k, or _s be in the in unsigned request
        if any([e[0] in REQUIRED_REQUEST_PARAMS_SET for e in query_params]):
            raise ValueError("Request query parameters can't include '{}'".format(
                "', '".join(REQUIRED_REQUEST_PARAMS_SET)))

    # Add timestamp and key
    query_params.extend([
        ('_ts', datetime.datetime.utcnow().strftime(TIMESTAMP_FORMAT)),
        ('_k', key)
    ])

    signature, query_string = compute_signature(
        url_parts.path, query_params, secret)
    return '{}://{}{}?{}&_s={}'.format(url_parts.scheme, url_parts.netloc,
        url_parts.path, query_string, signature)

QUERY_SIG_EXCLUDES = ['_s']

def compute_signature(path, query_params, secret):
    query_string = '&'.join(sorted([
        "%s=%s"%(e[0], e[1]) for e in query_params
        if e[0] != REQUIRED_REQUEST_PARAMS['signature']]))

    str_to_hash = secret.encode() + (''.join([path, query_string])).encode()
    tornado.log.gen_log.debug('string to hash %s', str_to_hash)
    return hashlib.sha256(str_to_hash).hexdigest(), query_string


class TornadoWebRequestAuthMetaClass(type):

    # def __init__(self, *args, **kwargs):
    #     tornado.log.gen_log.warn("in TornadoWebRequestAuthMetaClass.__init__")
    #     super(TornadoWebRequestAuthMetaClass, self).__init__(*args, **kwargs)

    HTTP_METHODS = ('get', 'post', 'put', 'delete')

    def __new__(meta, classname, supers, classdict):
        tornado.log.gen_log.debug("in TornadoWebRequestAuthMetaClass.__new__")
        for name, elem in classdict.items():
            if type(elem) is types.FunctionType and name in meta.HTTP_METHODS:
                classdict[name] = meta.authenticator(classdict[name])
        return super(TornadoWebRequestAuthMetaClass, meta).__new__(
            meta, classname, supers, classdict)

    # TODO: get this working as a class (with __init__ and __call__ methods)
    #    (When I implmented as a class, the first arg to decorated function
    #    wasn't the request handler class, which we need in order to access
    #    the request object
    def authenticator(func):

        def _get_request_arguments(request_handler):
            request_args = []
            for k,v in request_handler.request.query_arguments.items():
                if len(v) == 1:
                    request_args.append((k, v[0].decode('ascii')))
                else:
                    request_args.extend([(k, _v.decode('ascii')) for _v in v])
            return request_args

        def _check_for_auth_params(request_args):
            args_keys = set([e[0] for e in request_args])
            if not REQUIRED_REQUEST_PARAMS_SET.issubset(args_keys):
                message = "Request must include parameters '%s' for authentication" % (
                    "', '".join(REQUIRED_REQUEST_PARAMS_SET))
                # TODO: include message in response (not just in log)
                raise tornado.web.HTTPError(401, message)

        RECENCY_THRESHOLD = datetime.timedelta(minutes=10)

        def _get_arg_val(request_args, key, pretty_key):
            ts_vals = [e[1] for e in request_args if e[0] == key]
            if len(ts_vals) != 1:
                raise tornado.web.HTTPError(401,
                    'request must contain a single {} - {}'.format(
                    pretty_key, key))
            return ts_vals[0]


        def _check_recency(request_args):
            ts_val = _get_arg_val(request_args,
                REQUIRED_REQUEST_PARAMS['timestamp'], 'timestamp')
            ts = datetime.datetime.strptime(ts_val, TIMESTAMP_FORMAT)
            # Note: Using time.time() to get current time instead of
            # datetime.datetime.utcnow() to enable use of timecop in tests
            #now = datetime.datetime.fromtimestamp(time.time())
            now = datetime.datetime.utcnow()
            if abs(ts - now) > RECENCY_THRESHOLD:
                raise tornado.web.HTTPError(401, "Timestamp is not recent")

        async def _look_up_secret(request_args):
            key = _get_arg_val(request_args,
                REQUIRED_REQUEST_PARAMS['api_key'], 'api key')

            # TODO: look it up

            return 'e80556c6-70d8-11e6-a3ff-3c15c2c6639e'

        async def _authed(request_handler, *args, **kwargs):
            request_args = _get_request_arguments(request_handler)
            _check_for_auth_params(request_args)
            _check_recency(request_args)
            secret = await _look_up_secret(request_args)
            signature = _get_arg_val(request_args,
                REQUIRED_REQUEST_PARAMS['signature'], 'signature')
            computed_signature, query_string = compute_signature(
                request_handler.request.path, request_args, secret)

            if signature != computed_signature:
                raise tornado.web.HTTPError(401, "Invalid signature.")

            return func(request_handler, *args, **kwargs) # TODO: use `await`?
        return _authed


class authenticate(object):

    def __init__(self, enabled, api_clients, request_args_getter, request_path_getter,
            request_aborter, timestamp_format=None):
        """Initializer

        Arguments:
        api_clients -- dictionary contain
        request_args_getter -- a function that returns the request args
            dictionary
        request_path_getter -- a function that returns the request path
        request_aborter -- a function that aborts the request; takes two
            optional arguments - http status (which should defaults to 401)
            and message (which should default to authorized)
        """
        self.enabled = enabled
        self.api_clients = api_clients
        self.request_args_getter = request_args_getter
        self.request_path_getter = request_path_getter
        self.request_aborter = request_aborter
        self.timestamp_format = timestamp_format or TIMESTAMP_FORMAT

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
        if not REQUIRED_REQUEST_PARAMS_SET.issubset(list(self.request_args_getter().keys())):
            message = "Request must include parameters '%s' for authentication" % (
                "', '".join(REQUIRED_REQUEST_PARAMS_SET))
            self.request_aborter(401, message=message)



    RECENCY_THRESHOLD = datetime.timedelta(minutes=10)

    def _check_recency(self):
        ts_str = self.request_args_getter()[REQUIRED_REQUEST_PARAMS['timestamp']]
        ts = datetime.datetime.strptime(ts_str, self.timestamp_format)
        # Note: Using time.time() to get current time instead of
        # datetime.datetime.utcnow() to enable use of timecop in tests
        now = datetime.datetime.fromtimestamp(time.time())
        if abs(ts - now) > self.RECENCY_THRESHOLD:
            self.request_aborter(401, message="Timestamp is not recent")

    def _look_up_secret(self):
        api_key = self.request_args_getter()[REQUIRED_REQUEST_PARAMS['api_key']]
        if api_key not in self.api_clients:
            self.request_aborter(401, message='API key does not exist')

        return self.api_clients[api_key]


    def _get_request_signature(self):
        return self.request_args_getter()[REQUIRED_REQUEST_PARAMS['signature']]

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

