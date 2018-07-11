from asynctest import TestCase

from parameterized import parameterized

from async_hvac import AsyncClient
from async_hvac.tests.util import RequestsMocker


class TestGcpMethods(TestCase):
    """Unit tests providing coverage for GCP auth backend-related methods/routes."""

    @parameterized.expand([
        ("default mount point", "custom_role", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", None),
        ("custom mount point", "custom_role", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "gcp-not-default")
    ])
    @RequestsMocker()
    async def test_auth_gcp(self, test_label, test_role, test_jwt, mount_point, requests_mocker):
        mock_response = {
            'auth': {
                'accessor': 'accessor-1234-5678-9012-345678901234',
                'client_token': 'cltoken-1234-5678-9012-345678901234',
                'lease_duration': 10000,
                'metadata': {
                    'role': 'custom_role',
                    'service_account_email': 'dev1@project-123456.iam.gserviceaccount.com',
                    'service_account_id': '111111111111111111111'
                },
                'policies': [
                    'default',
                    'custom_role'
                ],
                'renewable': True
            },
            'data': None,
            'lease_duration': 0,
            'lease_id': '',
            'renewable': False,
            'request_id': 'requesti-1234-5678-9012-345678901234',
            'warnings': [],
            'wrap_info': None
        }
        mock_url = 'http://127.0.0.1:8200/v1/auth/{0}/login'.format(
                'gcp' if mount_point is None else mount_point)
        requests_mocker.register_uri(
            method='POST',
            url=mock_url,
            json=mock_response
        )
        client = AsyncClient()

        if mount_point is None:
            actual_response = await client.auth_gcp(
                role=test_role,
                jwt=test_jwt
            )
        else:
            actual_response = await client.auth_gcp(
                role=test_role,
                jwt=test_jwt,
                mount_point=mount_point
            )

        # ensure we received our mock response data back successfully
        self.assertEqual(mock_response, actual_response)
        await client.close()
