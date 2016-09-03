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

from flask import request
from flask.ext.restful import abort


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

# TODO: get this working as a class (with __init__ and __call__ methods)
#    (When I implmented as a class, the first arg to decorated function
#    wasn't the request handler class, which we need in order to access
#    the request object
def authenticator(func):
    """Generic decorator to be used by framework specific metaclasses, below
    """

    def _check_for_auth_params(request_args):
        args_keys = set([e[0] for e in request_args])
        if not REQUIRED_REQUEST_PARAMS_SET.issubset(args_keys):
            message = "Request must include parameters '%s' for authentication" % (
                "', '".join(REQUIRED_REQUEST_PARAMS_SET))
            # TODO: include message in response (not just in log)
            request_handler._request_aborter(401, message)

    RECENCY_THRESHOLD = datetime.timedelta(minutes=10)

    def _get_arg_val(request_args, key, pretty_key):
        ts_vals = [e[1] for e in request_args if e[0] == key]
        if len(ts_vals) != 1:
            request_handler._request_aborter(401,
                'request must contain a single {} - {}'.format(
                pretty_key, key))
        return ts_vals[0]


    def _check_recency(request_handler, request_args):
        ts_val = _get_arg_val(request_args,
            REQUIRED_REQUEST_PARAMS['timestamp'], 'timestamp')
        ts = datetime.datetime.strptime(ts_val, TIMESTAMP_FORMAT)
        # Note: This previously used time.time() to get current time
        #   instead of datetime.datetime.utcnow() to enable use of
        #   timecop in tests, but time.time returns system clock time
        #   which may in the be local timezone
        #now = datetime.datetime.fromtimestamp(time.time())
        now = datetime.datetime.utcnow()
        if abs(ts - now) > RECENCY_THRESHOLD:
            request_handler._request_aborter(401, "Timestamp is not recent")

    async def _look_up_secret(request_args):
        key = _get_arg_val(request_args,
            REQUIRED_REQUEST_PARAMS['api_key'], 'api key')

        # TODO: look it up

        return 'e80556c6-70d8-11e6-a3ff-3c15c2c6639e'

    async def _authed(request_handler, *args, **kwargs):
        request_args = request_handler._get_request_arguments()
        _check_for_auth_params(request_args)
        _check_recency(request_handler, request_args)
        secret = await _look_up_secret(request_args)
        signature = _get_arg_val(request_args,
            REQUIRED_REQUEST_PARAMS['signature'], 'signature')
        computed_signature, query_string = compute_signature(
            request_handler._get_request_path(), request_args, secret)

        if signature != computed_signature:
            request_handler._request_aborter(401, "Invalid signature.")

        return func(request_handler, *args, **kwargs) # TODO: use `await`?
    return _authed


##
## Framework specific metaclasses for adding authenticaiton to request handlers
##

class TornadoWebRequestAuthMetaClass(type):

    @staticmethod
    def _get_request_arguments(request_handler):
        request_args = []
        for k,v in request_handler.request.query_arguments.items():
            if len(v) == 1:
                request_args.append((k, v[0].decode('ascii')))
            else:
                request_args.extend([(k, _v.decode('ascii')) for _v in v])
        return request_args

    @staticmethod
    def _get_request_path(request_handler):
        return request_handler.request.path

    @staticmethod
    def _request_aborter(http_status, error_message):
        request_handler._request_aborter(http_status, error_message)

    # def __init__(self, name, bases, attrs):
    #     tornado.log.gen_log.debug("in TornadoWebRequestAuthMetaClass.__init__")
    #     super(TornadoWebRequestAuthMetaClass, self).__init__(name, bases, attrs)

    HTTP_METHODS = ('get', 'post', 'put', 'delete')

    def __new__(meta, classname, supers, classdict):
        tornado.log.gen_log.debug("in TornadoWebRequestAuthMetaClass.__new__")
        for name, elem in classdict.items():
            if type(elem) is types.FunctionType and name in meta.HTTP_METHODS:
                classdict[name] = authenticator(classdict[name])
        classdict['_get_request_arguments'] = meta._get_request_arguments
        classdict['_get_request_path'] = meta._get_request_path
        classdict['_request_aborter'] = meta._request_aborter
        return super(TornadoWebRequestAuthMetaClass, meta).__new__(
            meta, classname, supers, classdict)

class FlaskRequestAuthMetaClass(type):

    @staticmethod
    def _get_request_arguments(request_handler):
        # TODO: form list of tuples from request.args
        pass

    def __new__(meta, classname, supers, classdict):
        tornado.log.gen_log.debug("in FlaskRequestAuthMetaClass.__new__")
        for name, elem in classdict.items():
            if type(elem) is types.FunctionType and name in meta.HTTP_METHODS:
                classdict[name] = authenticator(classdict[name])
        classdict['_get_request_arguments'] = meta._get_request_arguments
        classdict['_get_request_path'] = lambda: request.path
        classdict['_request_aborter'] = lambda status=401, message='Unauthorized': abort(status, message=message)
        return super(FlaskRequestAuthMetaClass, meta).__new__(
            meta, classname, supers, classdict)


##
## decorator for adding basic auth
##

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

