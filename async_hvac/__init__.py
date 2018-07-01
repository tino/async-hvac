import asyncio
import concurrent

from async_hvac.v1 import AsyncClient


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


# Just for test and try and do not work properly in some cases... not part of the Async API
class Client(AsyncClient):

    def __init__(self, url='http://127.0.0.1:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, sync=True,
                 loop=None):
        super(Client, self).__init__(
            url, token, cert, verify, timeout,
            proxies, allow_redirects, session, loop)
        self._sync = sync
        if sync:
            for attr in AsyncClient.__dict__:
                attr_obj = getattr(AsyncClient, attr)
                if callable(attr_obj) and not attr.startswith('_'):
                    setattr(self, attr, async_to_sync(self, getattr(self, attr)))
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=3,
            )
            self._loop = asyncio.new_event_loop()
        else:
            if loop:
                self._loop = loop
            else:
                self._loop = asyncio.get_event_loop()

    @property
    def seal_status(self):
        if not self._sync or self._loop.is_running():
            return super(Client, self).seal_status
        return self._executor.submit(
            self._loop.run_until_complete,
            super(Client, self).seal_status).result()

    @property
    def generate_root_status(self):
        if not self._sync or self._loop.is_running():
            return super(Client, self).generate_root_status
        return self._executor.submit(
            self._loop.run_until_complete,
            super(Client, self).generate_root_status).result()

    @property
    def key_status(self):
        if not self._sync or self._loop.is_running():
            return super(Client, self).key_status
        return self._executor.submit(
            self._loop.run_until_complete,
            super(Client, self).key_status).result()

    @property
    def rekey_status(self):
        if not self._sync or self._loop.is_running():
            return super(Client, self).rekey_status
        return self._executor.submit(
            self._loop.run_until_complete,
            super(Client, self).rekey_status).result()

    @property
    def ha_status(self):
        if not self._sync or self._loop.is_running():
            return super(Client, self).ha_status
        return self._executor.submit(
            self._loop.run_until_complete,
            super(Client, self).ha_status).result()
