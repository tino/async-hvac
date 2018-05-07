import asyncio
import re
import subprocess
import time

from hvac import async_to_sync

from semantic_version import Spec, Version


class AsyncServerManager(object):
    def __init__(self, config_path, client):
        self.config_path = config_path
        self.client = client

        self.keys = None
        self.root_token = None

        self._process = None

    async def start(self):
        command = ['vault', 'server', '-config=' + self.config_path]

        self._process = subprocess.Popen(command,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

        attempts_left = 20
        last_exception = None
        while attempts_left > 0:
            try:
                await self.client.is_initialized()
                return
            except Exception as ex:
                print('Waiting for Vault to start')

                time.sleep(2)

                attempts_left -= 1
                last_exception = ex
        raise ex
        # raise Exception('Unable to start Vault in background: {0}'.format(last_exception))

    async def stop(self):
        await self.client.close()
        self._process.kill()

    async def initialize(self):
        assert not (await self.client.is_initialized())

        result = await self.client.initialize()

        assert (await self.client.is_initialized())

        self.root_token = result['root_token']
        self.keys = result['keys']

    async def unseal(self):
        return await self.client.unseal_multi(self.keys)


class ServerManager(AsyncServerManager):
    def __init__(self, config_path, client, sync=True):
        super(ServerManager, self).__init__(config_path, client)
        if sync:
            for attr in AsyncServerManager.__dict__:
                attr_obj = getattr(AsyncServerManager, attr)
                if callable(attr_obj) and not attr.startswith('_'):
                    setattr(self, attr, async_to_sync(getattr(self, attr)))


VERSION_REGEX = re.compile('Vault v([\d\.]+)')

def match_version(spec):
    output = subprocess.check_output(['vault', 'version']).decode('ascii')
    version = Version(VERSION_REGEX.match(output).group(1))

    return Spec(spec).match(version)
