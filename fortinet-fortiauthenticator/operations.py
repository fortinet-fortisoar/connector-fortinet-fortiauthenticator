"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests, json
import base64
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('fortinet-fortiauthenticator')

error_msgs = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
    503: 'Service Unavailable'
}


class FortiAuthenticator(object):
    def __init__(self, config):
        server_url = config.get('server', '')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            self.server_url = 'https://{0}/'.format(server_url)
        else:
            self.server_url = server_url + '/'
        self.username = config.get('username')
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            url = self.server_url + endpoint
            b64_credential = base64.b64encode((self.username + ":" + self.api_key).encode('utf-8')).decode()
            headers = {'Authorization': "Basic " + b64_credential, 'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, data=data, headers=headers, verify=self.verify_ssl)
            if response.ok:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.text})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid URL or Credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def _check_health(config):
    fa = FortiAuthenticator(config)
    try:
        response = fa.make_api_call(endpoint='api/v1/')
        if response:
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_schema(config, params):
    fa = FortiAuthenticator(config)
    return fa.make_api_call(endpoint='api/v1/')


def get_users(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    return fa.make_api_call(endpoint='api/v1/localusers/', params=params)


def get_local_user(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    mode = params.get('output_mode', '')
    if mode == 'ID':
        return fa.make_api_call(endpoint='api/v1/localusers/{0}/'.format(params.get('id')))
    else:
        return fa.make_api_call(endpoint='api/v1/localusers/', params=params)


def create_local_user(config, params):
    fa = FortiAuthenticator(config)
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.update(additional_fields)
    del params['additional_fields']
    params = get_params(params)
    return fa.make_api_call(endpoint='api/v1/localusers/', data=json.dumps(params), method='POST')


def update_user_status(config, params):
    fa = FortiAuthenticator(config)
    active = params.get('active')
    return fa.make_api_call(endpoint='api/v1/localusers/{0}/'.format(params.get('userid')),
                            data=json.dumps({'active': active}),
                            method='PATCH')


def get_ldap_user_list(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    return fa.make_api_call(endpoint='api/v1/ldapusers/', params=params)


def get_ldap_user(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    mode = params.get('output_mode', '')
    if mode == 'ID':
        return fa.make_api_call(endpoint='api/v1/ldapusers/{0}/'.format(params.get('id')))
    else:
        return fa.make_api_call(endpoint='api/v1/ldapusers/', params=params)


def update_ldapuser_status(config, params):
    fa = FortiAuthenticator(config)
    active = params.get('active')
    return fa.make_api_call(endpoint='api/v1/ldapusers/{0}/'.format(params.get('userid')),
                            data=json.dumps({'active': active}),
                            method='PATCH')


def get_radius_user_list(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    return fa.make_api_call(endpoint='api/v1/radiususers/', params=params)


def get_radius_user(config, params):
    fa = FortiAuthenticator(config)
    params = get_params(params)
    mode = params.get('output_mode', '')
    if mode == 'ID':
        return fa.make_api_call(endpoint='api/v1/radiususers/{0}/'.format(params.get('id')))
    else:
        return fa.make_api_call(endpoint='api/v1/radiususers/', params=params)


def update_radiususer_status(config, params):
    fa = FortiAuthenticator(config)
    active = params.get('active')
    return fa.make_api_call(endpoint='api/v1/radiususers/{0}/'.format(params.get('userid')),
                            data=json.dumps({'active': active}),
                            method='PATCH')


def get_userlockout_policy(config, params):
    fa = FortiAuthenticator(config)
    return fa.make_api_call(endpoint='api/v1/userlockoutpolicy/')

def execute_an_api_request(config, params):
    fa = FortiAuthenticator(config)
    endpoint = params.get("endpoint")
    http_method = params.get("method")
    query_params = params.get("params") if params.get("params") else None
    payload = json.dumps(params.get("data")) if params.get("data") else None
    response = fa.make_api_call(endpoint, data=payload, params=query_params, method=http_method)
    return response

operations = {
    'get_schema': get_schema,
    'get_users': get_users,
    'get_local_user': get_local_user,
    'create_local_user': create_local_user,
    'update_user_status': update_user_status,
    'get_ldap_user_list': get_ldap_user_list,
    'get_ldap_user': get_ldap_user,
    'update_ldapuser_status': update_ldapuser_status,
    'get_radius_user_list': get_radius_user_list,
    'get_radius_user': get_radius_user,
    'update_radiususer_status': update_radiususer_status,
    'get_userlockout_policy': get_userlockout_policy,
    'execute_an_api_request': execute_an_api_request
}
