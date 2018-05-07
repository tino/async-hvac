from unittest import TestCase

import asyncio

from hvac import Client, exceptions
from hvac.tests import util

loop = asyncio.get_event_loop()


def create_client(**kwargs):
    return Client(url='https://127.0.0.1:8200',
                  cert=('test/client-cert.pem', 'test/client-key.pem'),
                  verify='test/server-cert.pem',
                  sync=False,
                  **kwargs)


def async_test(f):
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        loop.run_until_complete(future)
    return wrapper


class IntegrationTest(TestCase):
    @classmethod
    @async_test
    def setUpClass(cls):
        cls.manager = util.ServerManager(
            config_path='test/vault-tls.hcl',
            client=create_client(), sync=False)
        yield from cls.manager.start()
        yield from cls.manager.initialize()
        yield from cls.manager.unseal()

    @classmethod
    @async_test
    def tearDownClass(cls):
        yield from cls.manager.stop()

    def root_token(self):
        cls = type(self)
        return cls.manager.root_token

    def setUp(self):
        self.client = create_client(token=self.root_token())

    @async_test
    def tearDown(self):
        yield from self.client.close()

    @async_test
    def test_unseal_multi(self):
        cls = type(self)

        yield from self.client.seal()

        keys = cls.manager.keys

        result = yield from self.client.unseal_multi(keys[0:2])

        assert result['sealed']
        assert result['progress'] == 2

        result = yield from self.client.unseal_multi(keys[2:3])

        assert not result['sealed']

    @async_test
    def test_seal_unseal(self):
        cls = type(self)

        assert not (yield from self.client.is_sealed())

        yield from self.client.seal()

        assert (yield from self.client.is_sealed())

        yield from cls.manager.unseal()

        assert not (yield from self.client.is_sealed())

    @async_test
    def test_ha_status(self):
        assert 'ha_enabled' in (yield from self.client.ha_status)

    @async_test
    def test_generic_secret_backend(self):
        yield from self.client.write('secret/foo', zap='zip')
        result = yield from self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        yield from self.client.delete('secret/foo')

    @async_test
    def test_list_directory(self):
        yield from self.client.write('secret/test-list/bar/foo', value='bar')
        yield from self.client.write('secret/test-list/foo', value='bar')
        result = yield from self.client.list('secret/test-list')

        assert result['data']['keys'] == ['bar/', 'foo']

        yield from self.client.delete('secret/test-list/bar/foo')
        yield from self.client.delete('secret/test-list/foo')

    @async_test
    def test_write_with_response(self):
        yield from self.client.enable_secret_backend('transit')

        plaintext = 'test'

        yield from self.client.write('transit/keys/foo')

        result = yield from self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = yield from self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    @async_test
    def test_wrap_write(self):
        if 'approle/' not in (yield from self.client.list_auth_backends()):
            yield from self.client.enable_auth_backend("approle")
        yield from self.client.write("auth/approle/role/testrole")

        result = yield from self.client.write('auth/approle/role/testrole/secret-id', wrap_ttl="10s")

        assert 'token' in result['wrap_info']

        yield from self.client.unwrap(result['wrap_info']['token'])
        yield from self.client.disable_auth_backend("approle")

    @async_test
    def test_read_nonexistent_key(self):
        assert not (yield from self.client.read('secret/I/dont/exist'))

    @async_test
    def test_auth_backend_manipulation(self):
        assert 'github/' not in (yield from self.client.list_auth_backends())

        yield from self.client.enable_auth_backend('github')
        assert 'github/' in (yield from self.client.list_auth_backends())

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('github')
        assert 'github/' not in (yield from self.client.list_auth_backends())

    @async_test
    def test_secret_backend_manipulation(self):
        assert 'test/' not in (yield from self.client.list_secret_backends())

        yield from self.client.enable_secret_backend('generic', mount_point='test')
        assert 'test/' in (yield from self.client.list_secret_backends())

        yield from self.client.remount_secret_backend('test', 'foobar')
        assert 'test/' not in (yield from self.client.list_secret_backends())
        assert 'foobar/' in (yield from self.client.list_secret_backends())

        self.client.token = self.root_token()
        yield from self.client.disable_secret_backend('foobar')
        assert 'foobar/' not in (yield from self.client.list_secret_backends())

    @async_test
    def test_audit_backend_manipulation(self):
        assert 'tmpfile/' not in (yield from self.client.list_audit_backends())

        options = {
            'path': '/tmp/vault.audit.log'
        }

        yield from self.client.enable_audit_backend('file', options=options, name='tmpfile')
        assert 'tmpfile/' in (yield from self.client.list_audit_backends())

        self.client.token = self.root_token()
        yield from self.client.disable_audit_backend('tmpfile')
        assert 'tmpfile/' not in (yield from self.client.list_audit_backends())

    async def prep_policy(self, name):
        text = """
        path "sys" {
          policy = "deny"
        }

        path "secret" {
          policy = "write"
        }
        """
        obj = {
            'path': {
                'sys': {
                    'policy': 'deny'},
                'secret': {
                    'policy': 'write'}
            }
        }

        await self.client.set_policy(name, text)

        return text, obj

    @async_test
    def test_policy_manipulation(self):
        assert 'root' in (yield from self.client.list_policies())
        assert (yield from self.client.get_policy('test')) is None

        policy, parsed_policy = yield from self.prep_policy('test')
        assert 'test' in (yield from self.client.list_policies())
        assert policy == (yield from self.client.get_policy('test'))
        assert parsed_policy == (yield from self.client.get_policy('test', parse=True))

        yield from self.client.delete_policy('test')
        assert 'test' not in (yield from self.client.list_policies())

    @async_test
    def test_json_policy_manipulation(self):
        assert 'root' in (yield from self.client.list_policies())

        yield from self.prep_policy('test')
        assert 'test' in (yield from self.client.list_policies())

        yield from self.client.delete_policy('test')
        assert 'test' not in (yield from self.client.list_policies())

    @async_test
    def test_auth_token_manipulation(self):
        result = yield from self.client.create_token(lease='1h', renewable=True)
        assert result['auth']['client_token']

        lookup = yield from self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

        renew = yield from self.client.renew_token(lookup['data']['id'])
        assert result['auth']['client_token'] == renew['auth']['client_token']

        yield from self.client.revoke_token(lookup['data']['id'])

        try:
            lookup = yield from self.client.lookup_token(result['auth']['client_token'])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    @async_test
    def test_userpass_auth(self):
        if 'userpass/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('userpass')

        yield from self.client.enable_auth_backend('userpass')

        yield from self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = yield from self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert (yield from self.client.is_authenticated())

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('userpass')

    @async_test
    def test_create_userpass(self):
        if 'userpass/' not in (yield from self.client.list_auth_backends()):
            yield from self.client.enable_auth_backend('userpass')

        yield from self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = yield from self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (yield from self.client.is_authenticated())

        # Test ttl:
        self.client.token = self.root_token()
        yield from self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root', ttl='10s')
        self.client.token = result['auth']['client_token']

        result = yield from self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert result['auth']['lease_duration'] == 10

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('userpass')

    @async_test
    def test_delete_userpass(self):
        if 'userpass/' not in (yield from self.client.list_auth_backends()):
            yield from self.client.enable_auth_backend('userpass')

        yield from self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = yield from self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (yield from self.client.is_authenticated())

        self.client.token = self.root_token()
        yield from self.client.delete_userpass('testcreateuser')
        with self.assertRaises(exceptions.InvalidRequest):
            yield from self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

    @async_test
    def test_app_id_auth(self):
        if 'app-id/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('app-id')

        yield from self.client.enable_auth_backend('app-id')

        yield from self.client.write('auth/app-id/map/app-id/foo', value='not_root')
        yield from self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = yield from self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert (yield from self.client.is_authenticated())

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('app-id')

    @async_test
    def test_create_app_id(self):
        if 'app-id/' not in (yield from self.client.list_auth_backends()):
            yield from self.client.enable_auth_backend('app-id')

        yield from self.client.create_app_id('testappid', policies='not_root', display_name='displayname')

        result = yield from self.client.read('auth/app-id/map/app-id/testappid')
        lib_result = yield from self.client.get_app_id('testappid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testappid'
        assert result['data']['display_name'] == 'displayname'
        assert result['data']['value'] == 'not_root'
        yield from self.client.delete_app_id('testappid')
        assert (yield from self.client.get_app_id('testappid'))['data'] is None

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('app-id')

    @async_test
    def test_create_user_id(self):
        if 'app-id/' not in (yield from self.client.list_auth_backends()):
            yield from self.client.enable_auth_backend('app-id')

        yield from self.client.create_app_id('testappid', policies='not_root', display_name='displayname')
        yield from self.client.create_user_id('testuserid', app_id='testappid')

        result = yield from self.client.read('auth/app-id/map/user-id/testuserid')
        lib_result = yield from self.client.get_user_id('testuserid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testuserid'
        assert result['data']['value'] == 'testappid'

        result = yield from self.client.auth_app_id('testappid', 'testuserid')

        assert self.client.token == result['auth']['client_token']
        assert (yield from self.client.is_authenticated())
        self.client.token = self.root_token()
        yield from self.client.delete_user_id('testuserid')
        assert (yield from self.client.get_user_id('testuserid'))['data'] is None

        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('app-id')

    @async_test
    def test_create_role(self):
        if 'approle/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('approle')
        yield from self.client.enable_auth_backend('approle')

        yield from self.client.create_role('testrole')

        result = yield from self.client.read('auth/approle/role/testrole')
        lib_result = yield from self.client.get_role('testrole')
        del result['request_id']
        del lib_result['request_id']

        assert result == lib_result
        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('approle')

    @async_test
    def test_create_delete_role_secret_id(self):
        if 'approle/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('approle')
        yield from self.client.enable_auth_backend('approle')

        yield from self.client.create_role('testrole')
        create_result = yield from self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        result = yield from self.client.get_role_secret_id('testrole', secret_id)
        assert result['data']['metadata']['foo'] == 'bar'
        yield from self.client.delete_role_secret_id('testrole', secret_id)
        assert (yield from self.client.get_role_secret_id('testrole', secret_id)) is None
        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('approle')

    @async_test
    def test_auth_approle(self):
        if 'approle/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('approle')
        yield from self.client.enable_auth_backend('approle')

        yield from self.client.create_role('testrole')
        create_result = yield from self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = yield from self.client.get_role_id('testrole')
        result = yield from self.client.auth_approle(role_id, secret_id)
        assert result['auth']['metadata']['foo'] == 'bar'
        self.client.token = self.root_token()
        yield from self.client.disable_auth_backend('approle')

    @async_test
    def test_missing_token(self):
        client = create_client()
        assert not (yield from client.is_authenticated())
        yield from client.close()

    @async_test
    def test_invalid_token(self):
        client = create_client(token='not-a-real-token')
        assert not (yield from client.is_authenticated())
        yield from client.close()

    @async_test
    def test_illegal_token(self):
        client = create_client(token='token-with-new-line\n')
        try:
            yield from client.is_authenticated()
        except ValueError as e:
            assert 'Invalid header value' in str(e)
        yield from client.close()

    @async_test
    def test_broken_token(self):
        client = create_client(token='\x1b')
        try:
            yield from client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)
        yield from client.close()

    @async_test
    def test_client_authenticated(self):
        assert (yield from self.client.is_authenticated())

    @async_test
    def test_client_logout(self):
        self.client.logout()
        assert not (yield from self.client.is_authenticated())

    @async_test
    def test_revoke_self_token(self):
        if 'userpass/' in (yield from self.client.list_auth_backends()):
            yield from self.client.disable_auth_backend('userpass')

        yield from self.client.enable_auth_backend('userpass')

        yield from self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = yield from self.client.auth_userpass('testuser', 'testpass')

        yield from self.client.revoke_self_token()
        assert not (yield from self.client.is_authenticated())

    @async_test
    def test_rekey_multi(self):
        cls = type(self)

        assert not (yield from self.client.rekey_status)['started']

        yield from self.client.start_rekey()
        assert (yield from self.client.rekey_status)['started']

        yield from self.client.cancel_rekey()
        assert not (yield from self.client.rekey_status)['started']

        result = yield from self.client.start_rekey()

        keys = cls.manager.keys

        result = yield from self.client.rekey_multi(keys, nonce=result['nonce'])
        assert result['complete']

        cls.manager.keys = result['keys']
        yield from cls.manager.unseal()

    @async_test
    def test_rotate(self):
        status = yield from self.client.key_status

        yield from self.client.rotate()

        assert (yield from self.client.key_status)['term'] > status['term']

    @async_test
    def test_tls_auth(self):
        yield from self.client.enable_auth_backend('cert')

        with open('test/client-cert.pem') as fp:
            certificate = fp.read()

        yield from self.client.write('auth/cert/certs/test', display_name='test',
                                     policies='not_root', certificate=certificate)

        result = yield from self.client.auth_tls()

    @async_test
    def test_gh51(self):
        key = 'secret/http://test.com'

        yield from self.client.write(key, foo='bar')

        result = yield from self.client.read(key)

        assert result['data']['foo'] == 'bar'

    @async_test
    def test_token_accessor(self):
        # Create token, check accessor is provided
        result = yield from self.client.create_token(lease='1h')
        token_accessor = result['auth'].get('accessor', None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = yield from self.client.lookup_token(token_accessor, accessor=True)
        assert lookup['data']['accessor'] == token_accessor
        assert not lookup['data']['id']

        # Revoke token using the accessor
        yield from self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = yield from self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = yield from self.client.lookup_token(result['auth']['client_token'])

    @async_test
    def test_wrapped_token_success(self):
        wrap = yield from self.client.create_token(wrap_ttl='1m')

        # Unwrap token
        result = yield from self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Validate token
        lookup = yield from self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

    @async_test
    def test_wrapped_token_intercept(self):
        wrap = yield from self.client.create_token(wrap_ttl='1m')

        # Intercept wrapped token
        _ = yield from self.client.unwrap(wrap['wrap_info']['token'])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            result = yield from self.client.unwrap(wrap['wrap_info']['token'])

    @async_test
    def test_wrapped_token_cleanup(self):
        wrap = yield from self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        _ = yield from self.client.unwrap(wrap['wrap_info']['token'])
        assert self.client.token == _token

    @async_test
    def test_wrapped_token_revoke(self):
        wrap = yield from self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        yield from self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        result = yield from self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            lookup = yield from self.client.lookup_token(result['auth']['client_token'])

    @async_test
    def test_create_token_explicit_max_ttl(self):

        token = yield from self.client.create_token(ttl='30m', explicit_max_ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = yield from self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    @async_test
    def test_create_token_max_ttl(self):

        token = yield from self.client.create_token(ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = yield from self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    @async_test
    def test_token_roles(self):
        # No roles, list_token_roles == None
        before = yield from self.client.list_token_roles()
        assert not before

        # Create token role
        assert (yield from self.client.create_token_role('testrole')).status == 204

        # List token roles
        during = (yield from self.client.list_token_roles())['data']['keys']
        assert len(during) == 1
        assert during[0] == 'testrole'

        # Delete token role
        yield from self.client.delete_token_role('testrole')

        # No roles, list_token_roles == None
        after = yield from self.client.list_token_roles()
        assert not after

    @async_test
    def test_create_token_w_role(self):
        # Create policy
        yield from self.prep_policy('testpolicy')

        # Create token role w/ policy
        assert (yield from self.client.create_token_role('testrole',
                                                         allowed_policies='testpolicy')).status == 204

        # Create token against role
        token = yield from self.client.create_token(lease='1h', role='testrole')
        assert token['auth']['client_token']
        assert token['auth']['policies'] == ['default', 'testpolicy']

        # Cleanup
        yield from self.client.delete_token_role('testrole')
        yield from self.client.delete_policy('testpolicy')
