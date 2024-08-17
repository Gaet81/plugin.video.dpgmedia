# -*- coding: utf-8 -*-
""" VTM GO Authentication API """

from __future__ import absolute_import, division, unicode_literals

import json
import logging
import os
import uuid
import xbmc

#login RTL
import re

from requests import HTTPError
from resources.lib import kodiutils
from resources.lib.vtmgo import API_ENDPOINT, Profile, util
from resources.lib.vtmgo.exceptions import NoLoginException

try:  # Python 3
    import jwt
except ImportError:  # Python 2
    # The package is named pyjwt in Kodi 18: https://github.com/lottaboost/script.module.pyjwt/pull/1
    import pyjwt as jwt

_LOGGER = logging.getLogger(__name__)

REFRESH_TOKEN_URL = 'https://lfvp-api.dpgmedia.net/%s/tokens/refresh'

#login gigya RTL
API_KEY = "3_LGnnaXIFQ_VRXofTaFTGnc6q7pM923yFB0AXSWdxADsUT0y2dVdDKmPRyQMj7LMc"
URL_COMPTE_LOGIN = 'https://accounts.eu1.gigya.com/accounts.login'

class AccountStorage:
    """ Data storage for account info """
    device_code = ''
    id_token = ''
    access_token = ''
    refresh_token = ''
    profile = ''
    product = ''
    #login RTL
    login_ok = False
    UIDSignature = ''
    signatureTimestamp = ''
    
    
    def is_valid_token(self):
        """ Validate the JWT to see if it's still valid.

        :rtype: boolean
        """
        if not self.access_token:
            # We have no token
            return False

        try:
            # Verify our token to see if it's still valid.
            decoded_jwt = jwt.decode(self.access_token,
                                     algorithms=['HS256'],
                                     options={'verify_signature': False, 'verify_aud': False})

            # Check expiration time
            from datetime import datetime

            import dateutil.parser
            import dateutil.tz
            exp = datetime.fromtimestamp(decoded_jwt.get('exp'), tz=dateutil.tz.gettz('Europe/Brussels'))
            now = datetime.now(dateutil.tz.UTC)
            if exp < now:
                _LOGGER.debug('JWT is expired at %s', exp.isoformat())
                return False

        except Exception as exc:  # pylint: disable=broad-except
            _LOGGER.debug('JWT is NOT valid: %s', exc)
            return False

        _LOGGER.debug('JWT is valid')
        return True


class VtmGoAuth:
    """ VTM GO Authentication API """

    TOKEN_FILE = 'auth-tokens2.json'

    def __init__(self, token_path):
        """ Initialise object """
        self._token_path = token_path

        # Load existing account data
        self._account = AccountStorage()
        self._load_cache()

    def set_token(self, access_token):
        """ Sets an auth token """
        self._account.access_token = access_token
        self._save_cache()

    def authorize(self,module):
        if module == 'VTM_GO':
            return self._authorizeVTM()    
        else:
            return self._authorizeRTL()
    
    def _authorizeVTM(self):    
        """ Start the authorization flow. """
        response = util.http_post('https://login2.vtm.be/device/authorize', form={
            'client_id': 'vtm-go-androidtv',
        })
        auth_info = json.loads(response.text)
        # We only need the device_code
        self._account.device_code = auth_info.get('device_code')
        self._save_cache()

        return auth_info
        
    def _authorizeRTL(self):
        login = kodiutils.get_setting('rtlplaybe.login')
        password = kodiutils.get_setting('rtlplaybe.password')
        if login == '' or password == '':
            kodiutils.notification(
                kodiutils.localize(30751),
                kodiutils.localize(30752) % ('RTLPlay (BE)', ('%s' % PUBLIC_SITE)))
            return
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/117.0",
            "Accept": "*/*",
            "Accept-Language": "fr-BE,en-US;q=0.7,en;q=0.3",
            "Content-Type": "application/x-www-form-urlencoded",
            "referrer": "https://cdns.eu1.gigya.com/"
        }
        
        payload = {
            "loginID": login,
            "password": password,
            "ApiKey": API_KEY,
            "lang": "fr",
            "format": "json"
        }
        
        resp2 = util.http_post(URL_COMPTE_LOGIN, form=payload, headers=headers)
        xbmc.log(resp2.text,xbmc.LOGINFO)
        auth_info = json.loads(resp2.text)
        if "UID" not in auth_info:
            kodiutils.notification('ERROR', 'RTLPlay (BE) : ' + kodiutils.localize(30753))
            return
    
        self._account.id_token = auth_info.get('UID')
        self._account.UIDSignature = auth_info.get('UIDSignature')
        self._account.access_token = auth_info.get('UIDSignature')       
        self._account.signatureTimestamp = auth_info.get('signatureTimestamp')
        self._account.login_ok = True
        self._save_cache() 
                  
        return auth_info

    def authorize_check(self):
        """ Check if the authorization has been completed. """
        if not self._account.device_code:
            raise NoLoginException

        try:
            response = util.http_post('https://login2.vtm.be/token', form={
                'device_code': self._account.device_code,
                'client_id': 'vtm-go-androidtv',
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            })
        except HTTPError as exc:
            if exc.response.status_code == 400:
                return False
            raise

        # Store these tokens
        auth_info = json.loads(response.text)
        self._account.id_token = auth_info.get('access_token')
        self._account.refresh_token = auth_info.get('refresh_token')

        # Fetch an actual token we can use
        response = util.http_post('https://lfvp-api.dpgmedia.net/VTM_GO/tokens', data={
            'device': {
                'id': str(uuid.uuid4()),
                'name': 'VTM Go Addon on Kodi',
            },
            'idToken': self._account.id_token,
        })

        self._account.access_token = json.loads(response.text).get('lfvpToken')
        self._save_cache()

        return True

    def get_tokens(self,module):
        """ Check if we have a token based on our device code. """
        # If we have no access_token, return None
        if not self._account.access_token:
            return None

        # Return our current token if it is still valid.
        if self._account.is_valid_token() and self._account.profile and self._account.product:
            return self._account

        # We can refresh our old token so it's valid again
        if self._account.module == 'VTM_GO'
        response = util.http_post(REFRESH_TOKEN_URL % module, data={
            'lfvpToken': self._account.access_token,
        })

        # Get JWT from reply
        self._account.access_token = json.loads(response.text).get('lfvpToken')

        # We always use the main profile
        profiles = self.get_profiles()
        self._account.profile = profiles[0].key
        self._account.product = profiles[0].product

        self._save_cache()

        return self._account

    def get_profiles(self):
        """ Returns the available profiles """
        response = util.http_get(API_ENDPOINT + '/VTM_GO/profiles', token=self._account.access_token)
        result = json.loads(response.text)

        profiles = [
            Profile(
                key=profile.get('id'),
                product=profile.get('product'),
                name=profile.get('name'),
                gender=profile.get('gender'),
                birthdate=profile.get('birthDate'),
                color=profile.get('color', {}).get('start'),
                color2=profile.get('color', {}).get('end'),
            )
            for profile in result.get('profiles')
        ]

        return profiles

    def logout(self):
        """ Clear the session tokens. """
        self._account.__dict__ = {}  # pylint: disable=attribute-defined-outside-init
        self._save_cache()

    def _load_cache(self):
        """ Load tokens from cache """
        try:
            with open(os.path.join(self._token_path, self.TOKEN_FILE), 'r') as fdesc:
                self._account.__dict__ = json.loads(fdesc.read())  # pylint: disable=attribute-defined-outside-init
        except (IOError, TypeError, ValueError):
            _LOGGER.warning('We could not use the cache since it is invalid or non-existent.')

    def _save_cache(self):
        """ Store tokens in cache """
        if not os.path.exists(self._token_path):
            os.makedirs(self._token_path)

        with open(os.path.join(self._token_path, self.TOKEN_FILE), 'w') as fdesc:
            json.dump(self._account.__dict__, fdesc, indent=2)
