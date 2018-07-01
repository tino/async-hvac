import re
import subprocess
import time
from aioresponses import aioresponses
import json as json_util


from semantic_version import Spec, Version


class ServerManager(object):

    def __init__(self, config_path, client):
        self.config_path = config_path
        self.client = client
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
        super(RequestsMocker, self).__init__()

    def register_uri(self, method='GET', url='', status_code=200, json=None):
        if json:
            json = json_util.dumps(json)
        else:
            json = ''
        if method == 'GET':
            self.get(url=url, status=status_code, body=json)
        if method == 'POST':
            self.post(url=url, status=status_code, body=json)
        if method == 'DELETE':
            self.delete(url=url, status=status_code, body=json)
