import asyncio
import concurrent
import re
import subprocess
import time
from aioresponses import aioresponses
import json as json_util


from semantic_version import Spec, Version

from async_hvac import AsyncClient


def async_to_sync(self, f):
    def wrapper(*args, **kwargs):
        if self._loop.is_running():
            return f(*args, **kwargs)
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        return self._executor.submit(
            self._loop.run_until_complete,
            future).result()
    return wrapper


class ServerManager(object):
    def __init__(self, config_path, client, loop=None):
        self.config_path = config_path
        self.client = client
        for attr in AsyncClient.__dict__:
            attr_obj = getattr(AsyncClient, attr)
            if callable(attr_obj) and not attr.startswith('_'):
                setattr(client, attr, async_to_sync(client, getattr(client, attr)))
        client._executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
        if loop:
            client._loop = loop
        else:
            client._loop = asyncio.new_event_loop()
        self.keys = None
        self.root_token = None

        self._process = None

    def start(self):
        command = ['vault', 'server', '-config=' + self.config_path]

        self._process = subprocess.Popen(command,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                self.client.is_initialized()
                return
            except Exception as ex:
                print('Waiting for Vault to start')

                time.sleep(.5)

                attempts_left -= 1
                last_exception = ex
        raise last_exception
        # raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    def stop(self):
        self.client.close()
        self._process.kill()

    def initialize(self):
        assert not self.client.is_initialized()

        result = self.client.initialize()

        assert self.client.is_initialized()

        self.root_token = result['root_token']
        self.keys = result['keys']

    def unseal(self):
        return self.client.unseal_multi(self.keys)



VERSION_REGEX = re.compile('Vault v([\d\.]+)')


def match_version(spec):
    output = subprocess.check_output(['vault', 'version']).decode('ascii')
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)


class RequestsMocker(aioresponses):

    def __init__(self):
        self.request_history = []
        super(RequestsMocker, self).__init__()

    def register_uri(self, method='GET', url='', status_code=200, json=None):
        if json:
            json = json_util.dumps(json)
        else:
            json = ''
        if method == 'GET':
            req = self.get(url=url, status=status_code, body=json)
        if method == 'POST':
            req = self.post(url=url, status=status_code, body=json)
        if method == 'DELETE':
            req = self.delete(url=url, status=status_code, body=json)
        self.request_history.append(req)