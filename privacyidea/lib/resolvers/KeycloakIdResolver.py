# -*- coding: utf-8 -*-
#
#
__doc__ = """This is the resolver to find users in a Keycloak service.

The file is tested in tests/test_lib_resolver.py
"""

import logging
import traceback

from .UserIdResolver import UserIdResolver
import yaml
import requests
import base64
from six.moves.urllib.parse import urlencode
from privacyidea.lib.utils import to_bytes, to_unicode, convert_column_to_unicode

log = logging.getLogger(__name__)


class KeycloakIdResolver(UserIdResolver):

    fields = {
        "keycloak_server": 1,
        "keycloak_realm": 1,
        "auth_client": 1,
        "auth_secret": 1,
        "access_token": 1,
    }

    def __init__(self):
        super(KeycloakIdResolver, self).__init__()
        self.config = {}

    def getUserInfo(self, userid):
        """
        returns the user information for a given uid.
        """
        ret = {}
        # The Keycloak ID is always /Users/ID
        # Alas, we can not map the ID to any other attribute
        res = self._get_user(self.config['keycloak_server'],
                             self.config['self.keycloak_realm'],
                             self.config['self.access_token'],
                             userid)
        user = res
        ret = self._fill_user_schema(user)

        return ret

    @staticmethod
    def _fill_user_schema(user):
        log.info("Fill user schema for {0!s}".format(user.get("username")))

        ret = {"phone": "", "email": "", "mobile": ""}
        ret['username'] = user.get("username", {})
        ret['givenname'] = user.get("firstName", {})
        ret['surname'] = user.get("lastName", {})
        ret['userid'] = user.get("id", {})
        ret['email'] = user.get("email")
        if user.get("attributes", {}):
            attributes = user.get("attributes", {});
            if attributes.get("mobile") and attributes.get("mobile")[0]:
                ret['mobile'] = user.get("attributes").get("mobile")[0]

        return ret

    def getUsername(self, userid):
        """
        Returns the username/loginname for a given userid
        :param userid: The userid in this resolver
        :type userid: string
        :return: username
        :rtype: string
        """
        user = self.getUserInfo(userid)
        return user.get("username", "")
        # It seems that the userName is the UserId
        # return userid

    def getUserId(self, loginName):
        """
        returns the uid for a given loginname/username
        :rtype: str
        """
        res = {}
        if self.access_token:
            res = self._search_users(self.config['keycloak_server'], self.config['keycloak_realm'], self.config['access_token'],
                                     {'username': loginName})
            num = len(res)
            desc = "Found {0!s} users".format(num)
            log.info(desc)

            if num != 1:
                info = "Could not find user '{0!s}'".format(loginName)
                log.error(info)
                raise Exception(info)

        return res[0].get("id")
        # It seems that the userName is the userId
        # return convert_column_to_unicode(loginName)

    def getUserList(self, searchDict=None):
        """
        Return the list of users
        """

        log.info("Will get user list...")

        ret = []

        res = {}
        if self.config['access_token']:
            res = self._search_users(self.config['keycloak_server'], self.config['keycloak_realm'], self.config['access_token'], "")

        for user in res:
            ret_user = self._fill_user_schema(user)

            ret.append(ret_user)

        return ret

    def getResolverId(self):
        """
        :return: the resolver identifier string, empty string if not exist
        """
        return self.config['keycloak_server'] if 'keycloak_server' in self.config else ''

    @staticmethod
    def getResolverClassType():
        return 'keycloakresolver'

    @staticmethod
    def getResolverDescriptor():
        return KeycloakIdResolver.getResolverClassDescriptor()

    @staticmethod
    def getResolverType():
        return KeycloakIdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.KeycloakIdResolver.IdResolver"
        descriptor['config'] = {'Keycloakserver': 'string',
                                'Realm': 'string',
                                'Client': 'string',
                                'Secret': 'string', }
        return {typ: descriptor}

    def loadConfig(self, config):
        """load the configuration to the Resolver instance

        Keys in the dict are
         * Authserver
         * Resouceserver
         * Client
         * Secret
         * Mapping

        :param config: the configuration dictionary
        :type config: dict
        :return: the resolver instance
        """
        self.config = config
        self.config['access_token'] = self.get_access_token(self.config['keycloak_server'],
                                                  self.config['keycloak_realm'],
                                                  self.config['auth_client'],
                                                  self.config['auth_secret'])
        return self

    @classmethod
    def testconnection(cls, param):
        """
        This function lets you test the to be saved Keycloak connection.

        :param param: A dictionary with all necessary parameter to test the
                        connection.
        :type param: dict
        :return: Tuple of success and a description
        :rtype: (bool, string)

        Parameters are: Keycloakserver, Client, Secret, Mapping
        """
        desc = None
        success = False

        try:
            access_token = cls.get_access_token(str(param.get("keycloak_server")),
                                                param.get("keycloak_realm"),
                                                param.get("auth_client"),
                                                param.get("auth_secret"))
            content = cls._search_users(param.get("keycloak_server"), param.get("keycloak_realm"), access_token, { "max": 10 })
            desc = "Found {0!s} users.".format(len(content))
            success = True
        except Exception as exx:
            log.error("Failed to retrieve users: {0!s}".format(exx))
            log.debug("{0!s}".format(traceback.format_exc()))
            desc = "failed to retrieve users: {0!s}".format(exx)

        return success, desc

    @staticmethod
    def _search_users(keycloak_server, keycloak_realm, access_token, params=None):
        """
        :param params: Additional http parameters added to the URL
        :type params: dictionary
        """
        params = params or { "max": 20 }
        headers = {'Authorization': "Bearer {0}".format(access_token),
                   'content-type': 'application/json'}
        url = '{0}/auth/admin/realms/{1}/users?{2}'.format(keycloak_server, keycloak_realm, urlencode(params))

        log.info("Will search for users at {0!s}".format(url))

        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code != 200:
            info = "Could not get user list: {0!s}".format(resp.status_code)
            log.error(info)
            raise Exception(info)
        j_content = resp.json()

        return j_content

    @staticmethod
    def _get_user(keycloak_server, keycloak_realm, access_token, userid):
        """
        Get a User from the Keycloak service

        :param keycloak_server: The Resource Server
        :type keycloak_server: basestring / URI
        :param access_token: Access Token
        :type access_token: basestring
        :param userid: The userid to fetch
        :type userid: basestring
        :return: Dictionary of User object.
        """
        log.info("Get user by {0}".format(userid))

        headers = {'Authorization': "Bearer {0}".format(access_token),
                   'content-type': 'application/json'}
        url = '{0}/auth/admin/realms/{1}/users/{2}'.format(keycloak_server, keycloak_realm, userid)

        resp = requests.get(url, headers=headers, verify=False)

        if resp.status_code != 200:
            info = "Could not get user: {0!s}".format(resp.status_code)
            log.error(info)
            raise Exception(info)
        j_content = yaml.safe_load(resp.content)

        return j_content

    @staticmethod
    def get_access_token(server=None, realm=None, client=None, secret=None):

        auth = to_unicode(base64.b64encode(to_bytes(client + ':' + secret)))

        payload = 'grant_type=client_credentials'
        headers = {
            'Authorization': 'Basic ' + auth,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        url = "{0!s}/auth/realms/{1!s}/protocol/openid-connect/token".format(server, realm)

        resp = requests.post(url, headers=headers, data=payload, verify=False)

        if resp.status_code != 200:
            info = "Could not get access token at {0!s}: {1!s} - {2!s}".format(url, resp.status_code, resp.reason)
            log.error(info)
            raise Exception(info)

        access_token = yaml.safe_load(resp.content).get('access_token')
        return access_token

