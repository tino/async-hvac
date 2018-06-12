from __future__ import unicode_literals

import asyncio
import concurrent
import json
import ssl

try:
    import hcl
    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False
import aiohttp

from async_hvac import exceptions

try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin


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


class AsyncClient(object):
    def __init__(self, url='http://127.0.0.1:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, loop=None):

        self.allow_redirects = allow_redirects
        self._session = session
        self.token = token

        self._url = url
        self._timeout = timeout
        self._verify = verify
        self._cert = cert
        self._proxies = proxies
        self._loop = loop
        self._sslcontext = None
        if self._verify and self._cert:
            self._sslcontext = ssl.create_default_context(cafile=self._verify)
            self._sslcontext.load_cert_chain(self._cert[0], self._cert[1])

    @property
    def session(self):
        if not self._session:
            self._session = aiohttp.ClientSession(
                loop=self._loop,
                timeout=aiohttp.ClientTimeout(total=self._timeout)
            )
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
            return await (await self._get('/v1/{}'.format(path), params=payload)).json()
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
        GET /cubbyhole/response
        X-Vault-Token: <token>
        """
        path = "cubbyhole/response"
        _token = self.token
        try:
            self.token = token
            return json.loads((await self.read(path))['data']['response'])
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

    async def unseal_reset(self):
        """
        PUT /sys/unseal
        """
        params = {
            'reset': True,
        }
        return await (await self._put('/v1/sys/unseal', json=params)).json()

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
        PUT /sys/leases/renew
        """
        params = {
            'lease_id': lease_id,
            'increment': increment,
        }
        return await (await self._post('/v1/sys/renew', json=params)).json()

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

    def tune_secret_backend(self, backend_type, mount_point=None, default_lease_ttl=None, max_lease_ttl=None):
        """
        POST /sys/mounts/<mount point>/tune
        """

        if not mount_point:
            mount_point = backend_type

        params = {
            'default_lease_ttl': default_lease_ttl,
            'max_lease_ttl': max_lease_ttl
        }

        return self._post('/v1/sys/mounts/{0}/tune'.format(mount_point), json=params)

    async def get_secret_backend_tuning(self, backend_type, mount_point=None):
        """
        GET /sys/mounts/<mount point>/tune
        """
        if not mount_point:
            mount_point = backend_type

        return await (await self._get('/v1/sys/mounts/{0}/tune'.format(mount_point))).json()

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

    async def create_token(self, role=None, token_id=None, policies=None, meta=None,
                           no_parent=False, lease=None, display_name=None,
                           num_uses=None, no_default_policy=False,
                           ttl=None, orphan=False, wrap_ttl=None, renewable=None,
                           explicit_max_ttl=None, period=None):
        """
        POST /auth/token/create
        POST /auth/token/create/<role>
        POST /auth/token/create-orphan
        """
        params = {
            'id': token_id,
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

        if period:
            params['period'] = period

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
                          allowed_policies=None, disallowed_policies=None,
                          orphan=None, period=None, renewable=None,
                          path_suffix=None, explicit_max_ttl=None):
        """
        POST /auth/token/roles/<role>
        """
        params = {
            'allowed_policies': allowed_policies,
            'disallowed_policies': disallowed_policies,
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

    async def auth_ec2(self, pkcs7, nonce=None, role=None, use_token=True):
        """
        POST /auth/aws-ec2/login
        """
        params = {'pkcs7': pkcs7}
        if nonce:
            params['nonce'] = nonce
        if role:
            params['role'] = role

        return await (await self.auth('/v1/auth/aws-ec2/login', json=params, use_token=use_token)).json()

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

        return self._post('/v1/auth/{}/users/{}'.format(mount_point, username), json=params)

    def delete_userpass(self, username, mount_point='userpass'):
        """
        DELETE /auth/<mount point>/users/<username>
        """
        return self._delete('/v1/auth/{}/users/{}'.format(mount_point, username))

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

        return self._post('/v1/auth/{}/map/app-id/{}'.format(mount_point, app_id), json=params)

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

        return self._post('/v1/auth/{}/map/user-id/{}'.format(mount_point, user_id), json=params)

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

    def create_ec2_role(self, role, bound_ami_id=None, bound_account_id=None, bound_iam_role_arn=None,
                        bound_iam_instance_profile_arn=None, role_tag=None, max_ttl=None, policies=None,
                        allow_instance_migration=False, disallow_reauthentication=False, **kwargs):
        """
        POST /auth/aws-ec2/role/<role>
        """
        params = {
            'role': role,
            'disallow_reauthentication': disallow_reauthentication,
            'allow_instance_migration': allow_instance_migration
        }
        if bound_ami_id is not None:
            params['bound_ami_id'] = bound_ami_id
        if bound_account_id is not None:
            params['bound_account_id'] = bound_account_id
        if bound_iam_role_arn is not None:
            params['bound_iam_role_arn'] = bound_iam_role_arn
        if bound_iam_instance_profile_arn is not None:
            params['bound_iam_instance_profile_arn'] = bound_iam_instance_profile_arn
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

    async def list_ec2_roles(self):
        """
        GET /auth/aws-ec2/roles?list=true
        """
        try:
            return await (await self._get('/v1/auth/aws-ec2/roles', params={'list': 'True'})).json()
        except exceptions.InvalidPath:
            return None

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

    async def create_role_secret_id(self, role_name, meta=None, cidr_list=None, wrap_ttl=None):
        """
        POST /auth/approle/role/<role name>/secret-id
        """

        url = '/v1/auth/approle/role/{0}/secret-id'.format(role_name)
        params = {}
        if meta is not None:
            params['metadata'] = json.dumps(meta)
        if cidr_list is not None:
            params['cidr_list'] = cidr_list
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

    def auth_approle(self, role_id, secret_id=None, mount_point='approle', use_token=True):
        """
        POST /auth/approle/login
        """
        params = {
            'role_id': role_id
        }
        if secret_id is not None:
            params['secret_id'] = secret_id

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def transit_create_key(self, name, convergent_encryption=None, derived=None, exportable=None,
                           key_type=None, mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        params = {}
        if convergent_encryption is not None:
            params['convergent_encryption'] = convergent_encryption
        if derived is not None:
            params['derived'] = derived
        if exportable is not None:
            params['exportable'] = exportable
        if key_type is not None:
            params['type'] = key_type

        return self._post(url, json=params)

    async def transit_read_key(self, name, mount_point='transit'):
        """
        GET /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return await (await self._get(url)).json()

    async def transit_list_keys(self, mount_point='transit'):
        """
        GET /<mount_point>/keys?list=true
        """
        url = '/v1/{0}/keys?list=true'.format(mount_point)
        return await (await self._get(url)).json()

    def transit_delete_key(self, name, mount_point='transit'):
        """
        DELETE /<mount_point>/keys/<name>
        """
        url = '/v1/{0}/keys/{1}'.format(mount_point, name)
        return self._delete(url)

    def transit_update_key(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                           mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>/config
        """
        url = '/v1/{0}/keys/{1}/config'.format(mount_point, name)
        params = {}
        if min_decryption_version is not None:
            params['min_decryption_version'] = min_decryption_version
        if min_encryption_version is not None:
            params['min_encryption_version'] = min_encryption_version
        if deletion_allowed is not None:
            params['deletion_allowed'] = deletion_allowed

        return self._post(url, json=params)

    def transit_rotate_key(self, name, mount_point='transit'):
        """
        POST /<mount_point>/keys/<name>/rotate
        """
        url = '/v1/{0}/keys/{1}/rotate'.format(mount_point, name)
        return self._post(url)

    async def transit_export_key(self, name, key_type, version=None, mount_point='transit'):
        """
        GET /<mount_point>/export/<key_type>/<name>(/<version>)
        """
        if version is not None:
            url = '/v1/{0}/export/{1}/{2}/{3}'.format(mount_point, key_type, name, version)
        else:
            url = '/v1/{0}/export/{1}/{2}'.format(mount_point, key_type, name)
        return await (await self._get(url)).json()

    async def transit_encrypt_data(self, name, plaintext, context=None, key_version=None, nonce=None, batch_input=None,
                             key_type=None, convergent_encryption=None, mount_point='transit'):
        """
        POST /<mount_point>/encrypt/<name>
        """
        url = '/v1/{0}/encrypt/{1}'.format(mount_point, name)
        params = {
            'plaintext': plaintext
        }
        if context is not None:
            params['context'] = context
        if key_version is not None:
            params['key_version'] = key_version
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input
        if key_type is not None:
            params['type'] = key_type
        if convergent_encryption is not None:
            params['convergent_encryption'] = convergent_encryption

        return await (await self._post(url, json=params)).json()

    async def transit_decrypt_data(self, name, ciphertext, context=None, nonce=None, batch_input=None, mount_point='transit'):
        """
        POST /<mount_point>/decrypt/<name>
        """
        url = '/v1/{0}/decrypt/{1}'.format(mount_point, name)
        params = {
            'ciphertext': ciphertext
        }
        if context is not None:
            params['context'] = context
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input

        return await (await self._post(url, json=params)).json()

    async def transit_rewrap_data(self, name, ciphertext, context=None, key_version=None, nonce=None, batch_input=None,
                            mount_point='transit'):
        """
        POST /<mount_point>/rewrap/<name>
        """
        url = '/v1/{0}/rewrap/{1}'.format(mount_point, name)
        params = {
            'ciphertext': ciphertext
        }
        if context is not None:
            params['context'] = context
        if key_version is not None:
            params['key_version'] = key_version
        if nonce is not None:
            params['nonce'] = nonce
        if batch_input is not None:
            params['batch_input'] = batch_input

        return await (await self._post(url, json=params)).json()

    async def transit_generate_data_key(self, name, key_type, context=None, nonce=None, bits=None, mount_point='transit'):
        """
        POST /<mount_point>/datakey/<type>/<name>
        """
        url = '/v1/{0}/datakey/{1}/{2}'.format(mount_point, key_type, name)
        params = {}
        if context is not None:
            params['context'] = context
        if nonce is not None:
            params['nonce'] = nonce
        if bits is not None:
            params['bits'] = bits

        return await (await self._post(url, json=params)).json()

    async def transit_generate_rand_bytes(self, data_bytes=None, output_format=None, mount_point='transit'):
        """
        POST /<mount_point>/random(/<data_bytes>)
        """
        if data_bytes is not None:
            url = '/v1/{0}/random/{1}'.format(mount_point, data_bytes)
        else:
            url = '/v1/{0}/random'.format(mount_point)

        params = {}
        if output_format is not None:
            params["format"] = output_format

        return await (await self._post(url, json=params)).json()

    async def transit_hash_data(self, hash_input, algorithm=None, output_format=None, mount_point='transit'):
        """
        POST /<mount_point>/hash(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/hash/{1}'.format(mount_point, algorithm)
        else:
            url = '/v1/{0}/hash'.format(mount_point)

        params = {
            'input': hash_input
        }
        if output_format is not None:
            params['format'] = output_format

        return await (await self._post(url, json=params)).json()

    async def transit_generate_hmac(self, name, hmac_input, key_version=None, algorithm=None, mount_point='transit'):
        """
        POST /<mount_point>/hmac/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/hmac/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/hmac/{1}'.format(mount_point, name)
        params = {
            'input': hmac_input
        }
        if key_version is not None:
            params['key_version'] = key_version

        return await (await self._post(url, json=params)).json()

    async def transit_sign_data(self, name, input_data, key_version=None, algorithm=None, context=None, prehashed=None,
                          mount_point='transit'):
        """
        POST /<mount_point>/sign/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/sign/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/sign/{1}'.format(mount_point, name)

        params = {
            'input': input_data
        }
        if key_version is not None:
            params['key_version'] = key_version
        if context is not None:
            params['context'] = context
        if prehashed is not None:
            params['prehashed'] = prehashed

        return await (await self._post(url, json=params)).json()

    async def transit_verify_signed_data(self, name, input_data, algorithm=None, signature=None, hmac=None, context=None,
                                   prehashed=None, mount_point='transit'):
        """
        POST /<mount_point>/verify/<name>(/<algorithm>)
        """
        if algorithm is not None:
            url = '/v1/{0}/verify/{1}/{2}'.format(mount_point, name, algorithm)
        else:
            url = '/v1/{0}/verify/{1}'.format(mount_point, name)

        params = {
            'input': input_data
        }
        if signature is not None:
            params['signature'] = signature
        if hmac is not None:
            params['hmac'] = hmac
        if context is not None:
            params['context'] = context
        if prehashed is not None:
            params['prehashed'] = prehashed

        return await (await self._post(url, json=params)).json()

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

        response = await self.session.request(
            method, url, headers=headers,
            allow_redirects=True,
            ssl=self._sslcontext,
            proxy=self._proxies, **kwargs)

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
