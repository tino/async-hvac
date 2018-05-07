from __future__ import unicode_literals

import asyncio
import json
import ssl

try:
    import hcl
    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False
import aiohttp

from hvac import exceptions

try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin

loop = asyncio.get_event_loop()


def async_to_sync(f):
    def wrapper(*args, **kwargs):
        if loop.is_running():
            return f(*args, **kwargs)
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        return loop.run_until_complete(future)
    return wrapper


class AsyncClient(object):
    def __init__(self, url='http://127.0.0.1:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None):

        self.allow_redirects = allow_redirects
        self._session = session
        self.token = token

        self._url = url
        self._kwargs = {
            'timeout': timeout,
        }
        self._verify = verify
        self._cert =  cert
        self._proxies = proxies

    @property
    def session(self):
        if not self._session:
            self._session = aiohttp.ClientSession()
        return self._session

    async def read(self, path, wrap_ttl=None):
        """
        GET /<path>
        """
        try:
            return await (await self._get('/v1/{0}'.format(path), wrap_ttl=wrap_ttl)).json()
        except exceptions.InvalidPath:
            return None

    async def list(self, path):
        """
        GET /<path>?list=true
        """
        try:
            payload = {
                'list': 'True'
            }
            return await (await self._get('/v1/{0}'.format(path), params=payload)).json()
        except exceptions.InvalidPath:
            return None

    async def write(self, path, wrap_ttl=None, **kwargs):
        """
        PUT /<path>
        """
        response = await self._put('/v1/{0}'.format(path), json=kwargs, wrap_ttl=wrap_ttl)

        if response.status == 200:
            return await response.json()

    def delete(self, path):
        """
        DELETE /<path>
        """
        return self._delete('/v1/{0}'.format(path))

    async def unwrap(self, token):
        """
        POST /sys/wrapping/unwrap
        X-Vault-Token: <token>
        """
        _token = self.token
        try:
            self.token = token
            return await (await self._post('/v1/sys/wrapping/unwrap')).json()
        finally:
            self.token = _token

    async def is_initialized(self):
        """
        GET /sys/init
        """
        return (await (await self._get('/v1/sys/init')).json())['initialized']

    async def initialize(self, secret_shares=5, secret_threshold=3, pgp_keys=None):
        """
        PUT /sys/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys
        return await (await self._put('/v1/sys/init', json=params)).json()

    @property
    async def seal_status(self):
        """
        GET /sys/seal-status
        """
        return await (await self._get('/v1/sys/seal-status')).json()

    async def is_sealed(self):
        return (await self.seal_status)['sealed']

    def seal(self):
        """
        PUT /sys/seal
        """
        return self._put('/v1/sys/seal')

    async def unseal(self, key):
        """
        PUT /sys/unseal
        """
        params = {
            'key': key,
        }
        return await (await self._put('/v1/sys/unseal', json=params)).json()

    async def unseal_multi(self, keys):
        result = None

        for key in keys:
            result = await self.unseal(key)
            if not result['sealed']:
                break

        return result

    @property
    async def key_status(self):
        """
        GET /sys/key-status
        """
        return await (await self._get('/v1/sys/key-status')).json()

    def rotate(self):
        """
        PUT /sys/rotate
        """
        return self._put('/v1/sys/rotate')

    @property
    async def rekey_status(self):
        """
        GET /sys/rekey/init
        """
        return await (await self._get('/v1/sys/rekey/init')).json()

    async def start_rekey(self, secret_shares=5, secret_threshold=3, pgp_keys=None,
                    backup=False):
        """
        PUT /sys/rekey/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys
            params['backup'] = backup

        resp = await self._put('/v1/sys/rekey/init', json=params)
        if resp.text:
            return await resp.json()

    def cancel_rekey(self):
        """
        DELETE /sys/rekey/init
        """
        return self._delete('/v1/sys/rekey/init')

    async def rekey(self, key, nonce=None):
        """
        PUT /sys/rekey/update
        """
        params = {
            'key': key,
        }

        if nonce:
            params['nonce'] = nonce

        return await (await self._put('/v1/sys/rekey/update', json=params)).json()

    async def rekey_multi(self, keys, nonce=None):
        result = None

        for key in keys:
            result = await self.rekey(key, nonce=nonce)
            if 'complete' in result and result['complete']:
                break

        return result

    async def get_backed_up_keys(self):
        """
        GET /sys/rekey/backup
        """
        return await (await self._get('/v1/sys/rekey/backup')).json()

    @property
    async def ha_status(self):
        """
        GET /sys/leader
        """
        return await (await self._get('/v1/sys/leader')).json()

    async def renew_secret(self, lease_id, increment=None):
        """
        PUT /sys/renew/<lease id>
        """
        params = {
            'increment': increment,
        }
        return await (await self._post('/v1/sys/renew/{0}'.format(lease_id), json=params)).json()

    def revoke_secret(self, lease_id):
        """
        PUT /sys/revoke/<lease id>
        """
        return self._put('/v1/sys/revoke/{0}'.format(lease_id))

    def revoke_secret_prefix(self, path_prefix):
        """
        PUT /sys/revoke-prefix/<path prefix>
        """
        return self._put('/v1/sys/revoke-prefix/{0}'.format(path_prefix))

    def revoke_self_token(self):
        """
        PUT /auth/token/revoke-self
        """
        return self._put('/v1/auth/token/revoke-self')

    async def list_secret_backends(self):
        """
        GET /sys/mounts
        """
        return await (await self._get('/v1/sys/mounts')).json()

    def enable_secret_backend(self, backend_type, description=None, mount_point=None, config=None):
        """
        POST /sys/auth/<mount point>
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'config': config,
        }

        return self._post('/v1/sys/mounts/{0}'.format(mount_point), json=params)

    def disable_secret_backend(self, mount_point):
        """
        DELETE /sys/mounts/<mount point>
        """
        return self._delete('/v1/sys/mounts/{0}'.format(mount_point))

    def remount_secret_backend(self, from_mount_point, to_mount_point):
        """
        POST /sys/remount
        """
        params = {
            'from': from_mount_point,
            'to': to_mount_point,
        }

        return self._post('/v1/sys/remount', json=params)

    async def list_policies(self):
        """
        GET /sys/policy
        """
        return (await (await self._get('/v1/sys/policy')).json())['policies']

    async def get_policy(self, name, parse=False):
        """
        GET /sys/policy/<name>
        """
        try:
            policy = (await (await self._get('/v1/sys/policy/{0}'.format(name))).json())['rules']
            if parse:
                if not has_hcl_parser:
                    raise ImportError('pyhcl is required for policy parsing')

                policy = hcl.loads(policy)

            return policy
        except exceptions.InvalidPath:
            return None

    def set_policy(self, name, rules):
        """
        PUT /sys/policy/<name>
        """

        if isinstance(rules, dict):
            rules = json.dumps(rules)

        params = {
            'rules': rules,
        }

        return self._put('/v1/sys/policy/{0}'.format(name), json=params)

    def delete_policy(self, name):
        """
        DELETE /sys/policy/<name>
        """
        return self._delete('/v1/sys/policy/{0}'.format(name))

    async def list_audit_backends(self):
        """
        GET /sys/audit
        """
        return await (await self._get('/v1/sys/audit')).json()

    def enable_audit_backend(self, backend_type, description=None, options=None, name=None):
        """
        POST /sys/audit/<name>
        """
        if not name:
            name = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'options': options,
        }

        return self._post('/v1/sys/audit/{0}'.format(name), json=params)

    def disable_audit_backend(self, name):
        """
        DELETE /sys/audit/<name>
        """
        return self._delete('/v1/sys/audit/{0}'.format(name))

    async def audit_hash(self, name, input):
        """
        POST /sys/audit-hash
        """
        params = {
            'input': input,
        }
        return await (await self._post('/v1/sys/audit-hash/{0}'.format(name), json=params)).json()

    async def create_token(self, role=None, id=None, policies=None, meta=None,
                     no_parent=False, lease=None, display_name=None,
                     num_uses=None, no_default_policy=False,
                     ttl=None, orphan=False, wrap_ttl=None, renewable=None,
                     explicit_max_ttl=None):
        """
        POST /auth/token/create
        POST /auth/token/create/<role>
        POST /auth/token/create-orphan
        """
        params = {
            'id': id,
            'policies': policies,
            'meta': meta,
            'no_parent': no_parent,
            'display_name': display_name,
            'num_uses': num_uses,
            'no_default_policy': no_default_policy,
            'renewable': renewable
        }

        if lease:
            params['lease'] = lease
        else:
            params['ttl'] = ttl
            params['explicit_max_ttl'] = explicit_max_ttl

        if explicit_max_ttl:
            params['explicit_max_ttl'] = explicit_max_ttl

        if orphan:
            return await (await self._post('/v1/auth/token/create-orphan', json=params, wrap_ttl=wrap_ttl)).json()
        elif role:
            return await (await self._post('/v1/auth/token/create/{0}'.format(role), json=params, wrap_ttl=wrap_ttl)).json()
        else:
            return await (await self._post('/v1/auth/token/create', json=params, wrap_ttl=wrap_ttl)).json()

    async def lookup_token(self, token=None, accessor=False, wrap_ttl=None):
        """
        GET /auth/token/lookup/<token>
        GET /auth/token/lookup-accessor/<token-accessor>
        GET /auth/token/lookup-self
        """
        if token:
            if accessor:
                path = '/v1/auth/token/lookup-accessor/{0}'.format(token)
                return await (await self._post(path, wrap_ttl=wrap_ttl)).json()
            else:
                return await (await self._get('/v1/auth/token/lookup/{0}'.format(token))).json()
        else:
            return await (await self._get('/v1/auth/token/lookup-self', wrap_ttl=wrap_ttl)).json()

    def revoke_token(self, token, orphan=False, accessor=False):
        """
        POST /auth/token/revoke/<token>
        POST /auth/token/revoke-orphan/<token>
        POST /auth/token/revoke-accessor/<token-accessor>
        """
        if accessor and orphan:
            msg = "revoke_token does not support 'orphan' and 'accessor' flags together"
            raise exceptions.InvalidRequest(msg)
        elif accessor:
            return self._post('/v1/auth/token/revoke-accessor/{0}'.format(token))
        elif orphan:
            return self._post('/v1/auth/token/revoke-orphan/{0}'.format(token))
        else:
            return self._post('/v1/auth/token/revoke/{0}'.format(token))

    async def revoke_token_prefix(self, prefix):
        """
        POST /auth/token/revoke-prefix/<prefix>
        """
        return self._post('/v1/auth/token/revoke-prefix/{0}'.format(prefix))

    async def renew_token(self, token=None, increment=None, wrap_ttl=None):
        """
        POST /auth/token/renew/<token>
        POST /auth/token/renew-self
        """
        params = {
            'increment': increment,
        }

        if token:
            path = '/v1/auth/token/renew/{0}'.format(token)
            return await (await self._post(path, json=params, wrap_ttl=wrap_ttl)).json()
        else:
            return await (await self._post('/v1/auth/token/renew-self', json=params, wrap_ttl=wrap_ttl)).json()

    def create_token_role(self, role,
                          allowed_policies=None, orphan=None, period=None,
                          renewable=None, path_suffix=None, explicit_max_ttl=None):
        """
        POST /auth/token/roles/<role>
        """
        params = {
            'allowed_policies': allowed_policies,
            'orphan': orphan,
            'period': period,
            'renewable': renewable,
            'path_suffix': path_suffix,
            'explicit_max_ttl': explicit_max_ttl
        }
        return self._post('/v1/auth/token/roles/{0}'.format(role), json=params)

    def token_role(self, role):
        """
        Returns the named token role.
        """
        return self.read('auth/token/roles/{0}'.format(role))

    def delete_token_role(self, role):
        """
        Deletes the named token role.
        """
        return self.delete('auth/token/roles/{0}'.format(role))

    def list_token_roles(self):
        """
        GET /auth/token/roles?list=true
        """
        return self.list('auth/token/roles')

    def logout(self, revoke_token=False):
        """
        Clears the token used for authentication, optionally revoking it before doing so
        """
        if revoke_token:
            return self.revoke_self_token()

        self.token = None

    async def is_authenticated(self):
        """
        Helper method which returns the authentication status of the client
        """
        if not self.token:
            return False

        try:
            await self.lookup_token()
            return True
        except exceptions.Forbidden:
            return False
        except exceptions.InvalidPath:
            return False
        except exceptions.InvalidRequest:
            return False

    def auth_app_id(self, app_id, user_id, mount_point='app-id', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_tls(self, mount_point='cert', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        return self.auth('/v1/auth/{0}/login'.format(mount_point), use_token=use_token)

    def auth_userpass(self, username, password, mount_point='userpass', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_ec2(self, pkcs7, nonce=None, role=None, use_token=True):
        """
        POST /auth/aws-ec2/login
        """
        params = {'pkcs7': pkcs7}
        if nonce:
            params['nonce'] = nonce
        if role:
            params['role'] = role

        return self.auth('/v1/auth/aws-ec2/login', json=params, use_token=use_token)

    def create_userpass(self, username, password, policies, mount_point='userpass', **kwargs):
        """
        POST /auth/<mount point>/users/<username>
        """

        # Users can have more than 1 policy. It is easier for the user to pass in the
        # policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(policies, (list, set, tuple)):
            policies = ','.join(policies)

        params = {
            'password': password,
            'policies': policies
        }
        params.update(kwargs)

        return self._post('/v1/auth/{0}/users/{1}'.format(mount_point, username), json=params)

    def delete_userpass(self, username, mount_point='userpass'):
        """
        DELETE /auth/<mount point>/users/<username>
        """
        return self._delete('/v1/auth/{0}/users/{1}'.format(mount_point, username))

    def create_app_id(self, app_id, policies, display_name=None, mount_point='app-id', **kwargs):
        """
        POST /auth/<mount point>/map/app-id/<app_id>
        """

        # app-id can have more than 1 policy. It is easier for the user to pass in the
        # policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(policies, (list, set, tuple)):
            policies = ','.join(policies)

        params = {
            'value': policies
        }

        # Only use the display_name if it has a value. Made it a named param for user
        # convienence instead of leaving it as part of the kwargs
        if display_name:
            params['display_name'] = display_name

        params.update(kwargs)

        return self._post('/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id), json=params)

    async def get_app_id(self, app_id, mount_point='app-id', wrap_ttl=None):
        """
        GET /auth/<mount_point>/map/app-id/<app_id>
        """
        path = '/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id)
        return await (await self._get(path, wrap_ttl=wrap_ttl)).json()

    def delete_app_id(self, app_id, mount_point='app-id'):
        """
        DELETE /auth/<mount_point>/map/app-id/<app_id>
        """
        return self._delete('/v1/auth/{0}/map/app-id/{1}'.format(mount_point, app_id))

    def create_user_id(self, user_id, app_id, cidr_block=None, mount_point='app-id', **kwargs):
        """
        POST /auth/<mount point>/map/user-id/<user_id>
        """

        # user-id can be associated to more than 1 app-id (aka policy). It is easier for the user to
        # pass in the policies as a list so if they do, we need to convert to a , delimited string.
        if isinstance(app_id, (list, set, tuple)):
            app_id = ','.join(app_id)

        params = {
            'value': app_id
        }

        # Only use the cidr_block if it has a value. Made it a named param for user
        # convienence instead of leaving it as part of the kwargs
        if cidr_block:
            params['cidr_block'] = cidr_block

        params.update(kwargs)

        return self._post('/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id), json=params)

    async def get_user_id(self, user_id, mount_point='app-id', wrap_ttl=None):
        """
        GET /auth/<mount_point>/map/user-id/<user_id>
        """
        path = '/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id)
        return await (await self._get(path, wrap_ttl=wrap_ttl)).json()

    def delete_user_id(self, user_id, mount_point='app-id'):
        """
        DELETE /auth/<mount_point>/map/user-id/<user_id>
        """
        return self._delete('/v1/auth/{0}/map/user-id/{1}'.format(mount_point, user_id))

    def create_vault_ec2_client_configuration(self, access_key, secret_key, endpoint=None):
        """
        POST /auth/aws-ec2/config/client
        """
        params = {
            'access_key': access_key,
            'secret_key': secret_key
        }
        if endpoint is not None:
            params['endpoint'] = endpoint

        return self._post('/v1/auth/aws-ec2/config/client', json=params)

    async def get_vault_ec2_client_configuration(self):
        """
        GET /auth/aws-ec2/config/client
        """
        return await (await self._get('/v1/auth/aws-ec2/config/client')).json()

    def delete_vault_ec2_client_configuration(self):
        """
        DELETE /auth/aws-ec2/config/client
        """
        return self._delete('/v1/auth/aws-ec2/config/client')

    def create_vault_ec2_certificate_configuration(self, cert_name, aws_public_cert):
        """
        POST /auth/aws-ec2/config/certificate/<cert_name>
        """
        params = {
            'cert_name': cert_name,
            'aws_public_cert': aws_public_cert
        }
        return self._post('/v1/auth/aws-ec2/config/certificate/{0}'.format(cert_name), json=params)

    async def get_vault_ec2_certificate_configuration(self, cert_name):
        """
        GET /auth/aws-ec2/config/certificate/<cert_name>
        """
        return await (await self._get('/v1/auth/aws-ec2/config/certificate/{0}'.format(cert_name))).json()

    async def list_vault_ec2_certificate_configurations(self):
        """
        GET /auth/aws-ec2/config/certificates?list=true
        """
        params = {'list': True}
        return await (await self._get('/v1/auth/aws-ec2/config/certificates', params=params)).json()

    def create_ec2_role(self, role, bound_ami_id, role_tag=None, max_ttl=None, policies=None,
                          allow_instance_migration=False, disallow_reauthentication=False, **kwargs):
        """
        POST /auth/aws-ec2/role/<role>
        """
        params = {
            'role': role,
            'bound_ami_id': bound_ami_id,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if role_tag is not None:
            params['role_tag'] = role_tag
        if max_ttl is not None:
            params['max_ttl'] = max_ttl
        if policies is not None:
            params['policies'] = policies
        params.update(**kwargs)
        return self._post('/v1/auth/aws-ec2/role/{0}'.format(role), json=params)

    async def get_ec2_role(self, role):
        """
        GET /auth/aws-ec2/role/<role>
        """
        return await (await self._get('/v1/auth/aws-ec2/role/{0}'.format(role))).json()

    def delete_ec2_role(self, role):
        """
        DELETE /auth/aws-ec2/role/<role>
        """
        return self._delete('/v1/auth/aws-ec2/role/{0}'.format(role))

    def list_ec2_roles(self):
        """
        GET /auth/aws-ec2/roles?list=true
        """
        return self._get('/v1/auth/aws-ec2/roles', params={'list': True})

    async def create_ec2_role_tag(self, role, policies=None, max_ttl=None, instance_id=None,
                            disallow_reauthentication=False, allow_instance_migration=False):
        """
        POST /auth/aws-ec2/role/<role>/tag
        """
        params = {
            'role': role,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if max_ttl is not None:
            params['max_ttl'] = max_ttl
        if policies is not None:
            params['policies'] = policies
        if instance_id is not None:
            params['instance_id'] = instance_id
        return await (await self._post('/v1/auth/aws-ec2/role/{0}/tag'.format(role), json=params)).json()

    def auth_ldap(self, username, password, mount_point='ldap', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    def auth_github(self, token, mount_point='github', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'token': token,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    async def auth(self, url, use_token=True, **kwargs):
        response = await (await self._post(url, **kwargs)).json()
        if use_token:
            self.token = response['auth']['client_token']

        return response

    async def list_auth_backends(self):
        """
        GET /sys/auth
        """
        return await (await self._get('/v1/sys/auth')).json()

    def enable_auth_backend(self, backend_type, description=None, mount_point=None):
        """
        POST /sys/auth/<mount point>
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
        }

        return self._post('/v1/sys/auth/{0}'.format(mount_point), json=params)

    def disable_auth_backend(self, mount_point):
        """
        DELETE /sys/auth/<mount point>
        """
        return self._delete('/v1/sys/auth/{0}'.format(mount_point))

    def create_role(self, role_name, **kwargs):
        """
        POST /auth/approle/role/<role name>
        """

        return self._post('/v1/auth/approle/role/{0}'.format(role_name), json=kwargs)

    async def list_roles(self):
        """
        GET /auth/approle/role
        """

        return await (await self._get('/v1/auth/approle/role?list=true')).json()

    async def get_role_id(self, role_name):
        """
        GET /auth/approle/role/<role name>/role-id
        """

        url = '/v1/auth/approle/role/{0}/role-id'.format(role_name)
        return (await (await self._get(url)).json())['data']['role_id']

    def set_role_id(self, role_name, role_id):
        """
        POST /auth/approle/role/<role name>/role-id
        """

        url = '/v1/auth/approle/role/{0}/role-id'.format(role_name)
        params = {
            'role_id': role_id
        }
        return self._post(url, json=params)


    async def get_role(self, role_name):
        """
        GET /auth/approle/role/<role name>
        """
        return await (await self._get('/v1/auth/approle/role/{0}'.format(role_name))).json()

    async def create_role_secret_id(self, role_name, meta=None, wrap_ttl=None):
        """
        POST /auth/approle/role/<role name>/secret-id
        """

        url = '/v1/auth/approle/role/{0}/secret-id'.format(role_name)
        params = {}
        if meta is not None:
            params['metadata'] = json.dumps(meta)

        return await (await self._post(url, json=params, wrap_ttl=wrap_ttl)).json()

    async def get_role_secret_id(self, role_name, secret_id):
        """
        POST /auth/approle/role/<role name>/secret-id/lookup
        """
        url = '/v1/auth/approle/role/{0}/secret-id/lookup'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        return await (await self._post(url, json=params)).json()

    async def list_role_secrets(self, role_name):
        """
        GET /auth/approle/role/<role name>/secret-id?list=true
        """
        url = '/v1/auth/approle/role/{0}/secret-id?list=true'.format(role_name)
        return await (await self._get(url)).json()

    async def get_role_secret_id_accessor(self, role_name, secret_id_accessor):
        """
        GET /auth/approle/role/<role name>/secret-id-accessor/<secret_id_accessor>
        """
        url = '/v1/auth/approle/role/{0}/secret-id-accessor/{1}'.format(role_name, secret_id_accessor)
        return await (await self._get(url)).json()

    def delete_role_secret_id(self, role_name, secret_id):
        """
        POST /auth/approle/role/<role name>/secret-id/destroy
        """
        url = '/v1/auth/approle/role/{0}/secret-id/destroy'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        return self._post(url, json=params)

    def delete_role_secret_id_accessor(self, role_name, secret_id_accessor):
        """
        DELETE /auth/approle/role/<role name>/secret-id/<secret_id_accessor>
        """
        url = '/v1/auth/approle/role/{0}/secret-id-accessor/{1}'.format(role_name, secret_id_accessor)
        return self._delete(url)

    async def create_role_custom_secret_id(self, role_name, secret_id, meta=None):
        """
        POST /auth/approle/role/<role name>/custom-secret-id
        """
        url = '/v1/auth/approle/role/{0}/custom-secret-id'.format(role_name)
        params = {
            'secret_id': secret_id
        }
        if meta is not None:
            params['meta'] = meta
        return await (await self._post(url, json=params)).json()

    def auth_approle(self, role_id, secret_id=None, use_token=True):
        """
        POST /auth/approle/login
        """
        params = {
            'role_id': role_id
        }
        if secret_id is not None:
            params['secret_id'] = secret_id

        return self.auth('/v1/auth/approle/login', json=params, use_token=use_token)

    def close(self):
        """
        Close the underlying Requests session
        """
        return self.session.close()

    def _get(self, url, **kwargs):
        return self.__request('get', url, **kwargs)

    def _post(self, url, **kwargs):
        return self.__request('post', url, **kwargs)

    def _put(self, url, **kwargs):
        return self.__request('put', url, **kwargs)

    def _delete(self, url, **kwargs):
        return self.__request('delete', url, **kwargs)

    async def __request(self, method, url, headers=None, **kwargs):
        url = urljoin(self._url, url)

        if not headers:
            headers = {}

        if self.token:
            headers['X-Vault-Token'] = self.token

        wrap_ttl = kwargs.pop('wrap_ttl', None)
        if wrap_ttl:
            headers['X-Vault-Wrap-TTL'] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        sslcontext = None
        if self._verify and self._cert:
            sslcontext = ssl.create_default_context(cafile=self._verify)
            sslcontext.load_cert_chain(self._cert[0], self._cert[1])

        response = await self.session.request(
            method, url, headers=headers,
            allow_redirects=True,
            ssl=sslcontext,
            proxy=self._proxies, **_kwargs)

        if response.status >= 400 and response.status < 600:
            text = errors = None
            if response.headers.get('Content-Type') == 'application/json':
                errors = (await response.json()).get('errors')
            if errors is None:
                text = response.text
            self.__raise_error(response.status, text, errors=errors)

        return response

    def __raise_error(self, status_code, message=None, errors=None):
        if status_code == 400:
            raise exceptions.InvalidRequest(message, errors=errors)
        elif status_code == 401:
            raise exceptions.Unauthorized(message, errors=errors)
        elif status_code == 403:
            raise exceptions.Forbidden(message, errors=errors)
        elif status_code == 404:
            raise exceptions.InvalidPath(message, errors=errors)
        elif status_code == 429:
            raise exceptions.RateLimitExceeded(message, errors=errors)
        elif status_code == 500:
            raise exceptions.InternalServerError(message, errors=errors)
        elif status_code == 501:
            raise exceptions.VaultNotInitialized(message, errors=errors)
        elif status_code == 503:
            raise exceptions.VaultDown(message, errors=errors)
        else:
            raise exceptions.UnexpectedError(message)


class Client(AsyncClient):

    def __init__(self, url='http://127.0.0.1:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, sync=True):
        super(Client, self).__init__(
            url, token, cert, verify, timeout,
            proxies, allow_redirects, session)
        self._sync = sync
        if sync:
            for attr in AsyncClient.__dict__:
                attr_obj = getattr(AsyncClient, attr)
                if callable(attr_obj) and not attr.startswith('_'):
                    setattr(self, attr, async_to_sync(getattr(self, attr)))

    @property
    def seal_status(self):
        if not self._sync or loop.is_running():
            return super(Client, self).seal_status
        return loop.run_until_complete(super(Client, self).seal_status)

    @property
    def key_status(self):
        if not self._sync or loop.is_running():
            return super(Client, self).key_status
        return loop.run_until_complete(super(Client, self).key_status)

    @property
    def rekey_status(self):
        if not self._sync or loop.is_running():
            return super(Client, self).rekey_status
        return loop.run_until_complete(super(Client, self).rekey_status)

    @property
    def ha_status(self):
        if not self._sync or loop.is_running():
            return super(Client, self).ha_status
        return loop.run_until_complete(super(Client, self).ha_status)
