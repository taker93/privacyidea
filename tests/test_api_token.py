# -*- coding: utf-8 -*-

from .base import MyApiTestCase
import json
import os
import datetime
import codecs
from mock import mock
from privacyidea.lib.policy import (set_policy, delete_policy, SCOPE, ACTION,
                                    enable_policy,
                                    PolicyClass)
from privacyidea.lib.token import (get_tokens, init_token, remove_token, get_tokens_from_serial_or_user, enable_token,
                                   check_serial_pass, get_realms_of_token, assign_token)
from privacyidea.lib.user import User
from privacyidea.lib.event import set_event, delete_event, EventConfiguration
from privacyidea.lib.caconnector import save_caconnector
from six.moves.urllib.parse import urlencode
from privacyidea.lib.tokenclass import DATE_FORMAT
from privacyidea.lib.config import set_privacyidea_config, delete_privacyidea_config
from dateutil.tz import tzlocal
from privacyidea.lib import _

IMPORTFILE = "tests/testdata/import.oath"
IMPORTFILE_GPG = "tests/testdata/import.oath.asc"
IMPORTFILE2 = "tests/testdata/empty.oath"
IMPORTPSKC = "tests/testdata/pskc-aes.xml"
IMPORTPSKC_PASS = "tests/testdata/pskc-password.xml"
PSK_HEX = "12345678901234567890123456789012"
YUBICOFILE = "tests/testdata/yubico-oath.csv"
YUBICOFILE_LONG = "tests/testdata/yubico-oath-long.csv"
OTPKEY = "3132333435363738393031323334353637383930"
OTPKEY2 = "010fe88d31948c0c2e3258a4b0f7b11956a258ef"
CAKEY = "cakey.pem"
CACERT = "cacert.pem"
OPENSSLCNF = "openssl.cnf"
WORKINGDIR = "tests/testdata/ca"
REQUEST = """-----BEGIN CERTIFICATE REQUEST-----
MIICmTCCAYECAQAwVDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkhlc3NlbjEUMBIG
A1UECgwLcHJpdmFjeWlkZWExHjAcBgNVBAMMFXJlcXVlc3Rlci5sb2NhbGRvbWFp
bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2+FE/6zgE/QiIbHZyv
3ZLSf9tstz45Q0NrEwPxBfQHdLx2aSgLrxmO1/zjzcZY8sp/CG1T/AcCRCTGtDRM
jAT+Mw5A4iC6AnNa9/VPY27MxrbfVB03OX1RNiZfvdw/qItroq62ndYh599BuHoo
KmhIyqgt7eHpRl5acm20hDiHkf2UEQsohMbCLyr7Afk2egl10TOIPHNBW8i/lIlw
ofDAuS5QUx6xF2Rp9C2B4KkNDjLpulWKhfEbb0l5tH+Iww0+VIibPR84jATz7mpj
K/XG27SDqsR4QTp9S+HIPnHKG2FZ6sbEyjJeyem/EinmxsNj/qBV2nrxYJhNJu36
cC0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQB7uJC6I1By0T29IZ0B1ue5YNxM
NDPbqCytRPMQ9awJ6niMMIQRS1YPhSFPWyEWrGKWAUvbn/lV0XHH7L/tvHg6HbC0
AjLc8qPH4Xqkb1WYV1GVJYr5qyEFS9QLZQLQDC2wk018B40MSwZWtsv14832mPu8
gP5WP+mj9LRgWCP1MdAR9pcNGd9pZMcCHQLxT76mc/eol4kb/6/U6yxBmzaff8eB
oysLynYXZkm0wFudTV04K0aKlMJTp/G96sJOtw1yqrkZSe0rNVcDs9vo+HAoMWO/
XZp8nprZvJuk6/QIRpadjRkv4NElZ2oNu6a8mtaO38xxnfQm4FEMbm5p+4tM
-----END CERTIFICATE REQUEST-----"""


class API000TokenAdminRealmList(MyApiTestCase):

    def test_000_setup_realms(self):
        self.setUp_user_realms()

        self.setUp_user_realms()

        # create tokens
        t = init_token({"otpkey": self.otpkey},
                       tokenrealms=[self.realm1])

        t = init_token({"otpkey": self.otpkey},
                       tokenrealms=[self.realm2])

    def test_01_test_two_tokens(self):
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            # we have two tokens
            self.assertEqual(2, result.get("value").get("count"))

        # admin is allowed to see realm1
        set_policy(name="pol-realm1",
                   scope=SCOPE.ADMIN,
                   action="tokenlist", user="testadmin", realm=self.realm1)

        # admin is allowed to list all realms
        set_policy(name="pol-all-realms",
                   scope=SCOPE.ADMIN,
                   action="tokenlist", user="testadmin")

        # admin is allowed to only init, not list
        set_policy(name="pol-only-init",
                   scope=SCOPE.ADMIN)

        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            # we have two tokens
            self.assertEqual(2, result.get("value").get("count"))

        # Disable to be allowed to list all realms
        enable_policy("pol-all-realms", False)

        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            # we have one token
            self.assertEqual(1, result.get("value").get("count"))
            # The token is in realm1
            self.assertEqual(self.realm1,
                             result.get("value").get("tokens")[0].get("realms")[0])

        # Disable to be allowed to list realm1
        enable_policy("pol-realm1", False)

        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            # we have two tokens
            self.assertEqual(0, result.get("value").get("count"))


class APIAttestationTestCase(MyApiTestCase):

    def test_00_realms_and_ca(self):
        # Setup realms and CA
        self.setUp_user_realms()
        cwd = os.getcwd()
        # setup ca connector
        r = save_caconnector({"cakey": CAKEY,
                              "cacert": CACERT,
                              "type": "local",
                              "caconnector": "localCA",
                              "openssl.cnf": OPENSSLCNF,
                              "CSRDir": "",
                              "CertificateDir": "",
                              "WorkingDir": cwd + "/" + WORKINGDIR})

    def test_01_enroll_certificate(self):
        # Enroll a certificate without a policy
        from .test_lib_tokens_certificate import YUBIKEY_CSR, BOGUS_ATTESTATION, YUBIKEY_ATTEST, ACTION

        # A bogus attestation certificate will fail!
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "certificate",
                                                 "request": YUBIKEY_CSR,
                                                 "attestation": BOGUS_ATTESTATION,
                                                 "ca": "localCA"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            result = res.json.get("result")
            self.assertEqual(400, res.status_code)
            self.assertEqual(10, result.get("error").get("code"))
            self.assertEqual('ERR10: certificate request does not match attestation certificate.',
                             result.get("error").get("message"))

        # If a valid attestation certificate can not be verified due to missing CA path, we will fail.
        from privacyidea.lib.tokens.certificatetoken import ACTION, REQUIRE_ACTIONS
        set_policy(name="pol_verify",
                   scope=SCOPE.ENROLL,
                   action="{0!s}={1!s}".format(ACTION.REQUIRE_ATTESTATION, REQUIRE_ACTIONS.REQUIRE_AND_VERIFY))
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "certificate",
                                                 "request": YUBIKEY_CSR,
                                                 "attestation": YUBIKEY_ATTEST,
                                                 "ca": "localCA"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            result = res.json.get("result")
            self.assertEqual(400, res.status_code)
            self.assertEqual(10, result.get("error").get("code"))
            self.assertEqual('ERR10: Failed to verify certificate chain of attestation certificate.',
                             result.get("error").get("message"))

        # The admin enrolls the certificate, so we need an admin policy
        set_policy("pol1", scope=SCOPE.ADMIN,
                   action="{0!s}=tests/testdata/attestation/".format(ACTION.TRUSTED_CA_PATH))
        set_policy("pol2", scope=SCOPE.ADMIN,
                   action="enrollCERTIFICATE")

        # If the attestation certificate matches and it is trusted, then we succeed.
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "certificate",
                                                 "request": YUBIKEY_CSR,
                                                 "attestation": YUBIKEY_ATTEST,
                                                 "ca": "localCA"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            result = res.json.get("result")
            self.assertEqual(200, res.status_code)
            self.assertTrue(result.get("value"))

        delete_policy("pol1")
        delete_policy("pol2")
        delete_policy("pol_verify")

class APITokenTestCase(MyApiTestCase):

    def _create_temp_token(self, serial):
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"serial": serial,
                                                 "genkey": 1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)

    def test_000_setup_realms(self):
        self.setUp_user_realms()

    def test_00_init_token(self):
        # hmac is now hotp.
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "hmac"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        # missing parameter otpkey
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "hotp"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "hotp",
                                                 "otpkey": self.otpkey},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            self.assertTrue(result.get("status"), result)
            self.assertTrue(result.get("value"), result)
            self.assertTrue("value" in detail.get("googleurl"), detail)
            self.assertTrue("OATH" in detail.get("serial"), detail)

        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "hotp",
                                                 "otpkey": self.otpkey,
                                                 "genkey": 0},
                                           headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                data = res.json
                self.assertTrue(res.status_code == 200, res)
                result = data.get("result")
                detail = data.get("detail")
                self.assertTrue(result.get("status"), result)
                self.assertTrue(result.get("value"), result)
                self.assertTrue("value" in detail.get("googleurl"), detail)
                serial = detail.get("serial")
                self.assertTrue("OATH" in serial, detail)
        remove_token(serial)

        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "HOTP",
                                                 "otpkey": self.otpkey,
                                                 "pin": "1234",
                                                 "user": "cornelius",
                                                 "realm": self.realm1},
                                           headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                data = res.json
                self.assertTrue(res.status_code == 200, res)
                result = data.get("result")
                detail = data.get("detail")
                self.assertTrue(result.get("status"), result)
                self.assertTrue(result.get("value"), result)
                self.assertTrue("value" in detail.get("googleurl"), detail)
                serial = detail.get("serial")
                self.assertTrue("OATH" in serial, detail)
        remove_token(serial)

    def test_01_list_tokens(self):
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            count = result.get("value").get("count")
            next = result.get("value").get("next")
            prev = result.get("value").get("prev")
            self.assertTrue(result.get("status"), result)
            self.assertEqual(len(tokenlist), 1)
            self.assertTrue(count == 1, count)
            self.assertTrue(next is None, next)
            self.assertTrue(prev is None, prev)
            token0 = tokenlist[0]
            self.assertTrue(token0.get("username") == "", token0)
            self.assertTrue(token0.get("count") == 0, token0)
            self.assertTrue(token0.get("tokentype") == "hotp", token0)
            self.assertTrue(token0.get("tokentype") == "hotp", token0)
            self.assertTrue(token0.get("count_window") == 10, token0)
            self.assertTrue(token0.get("realms") == [], token0)
            self.assertTrue(token0.get("user_realm") == "", token0)

        # get assigned tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "assigned": True}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            # NO token assigned, yet
            self.assertTrue(len(tokenlist) == 0, "{0!s}".format(tokenlist))

        # get unassigned tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "assigned": False}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            self.assertTrue(len(tokenlist) == 1, len(tokenlist))

        # prepare active tests
        init_token({"serial": "totp1", "genkey": 1}, tokenkind="totp")
        enable_token("totp1", enable=False)
        # get active tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "active": True}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            # NO token assigned, yet
            self.assertTrue(len(tokenlist) == 1, "{0!s}".format(tokenlist))

        # get inactive tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "active": False}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            self.assertTrue(len(tokenlist) == 1, len(tokenlist))
            token0 = tokenlist[0]
            self.assertTrue(token0.get("serial") == "totp1", token0)

        # get all tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            self.assertTrue(len(tokenlist) == 2, len(tokenlist))

        remove_token(serial="totp1")

        # get tokens with a specific tokeninfo
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "assigned": False,
                                           "infokey": "tokenkind",
                                           "infovalue": "hardware"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            self.assertEqual(len(tokenlist), 0)

        init_token({"serial": "hw001", "genkey": 1}, tokenkind="hardware")
        # get tokens with a specific tokeninfo
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "assigned": False,
                                               "infokey": "tokenkind",
                                               "infovalue": "hardware"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            self.assertEqual(len(tokenlist), 1)

        remove_token("hw001")

    def test_02_list_tokens_csv(self):
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({"outform": "csv"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            self.assertEqual(res.mimetype, 'text/csv', res)
            self.assertTrue(b"info" in res.data, res.data)
            self.assertTrue(b"username" in res.data, res.data)
            self.assertTrue(b"user_realm" in res.data, res.data)

    def test_03_list_tokens_in_one_realm(self):
        for serial in ["S1", "S2", "S3", "S4"]:
             with self.app.test_request_context('/token/init',
                                                method='POST',
                                                data={"type": "hotp",
                                                      "otpkey": self.otpkey,
                                                      "serial": serial},
                                                headers={'Authorization':
                                                             self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)

        # tokens with realm
        for serial in ["R1", "R2"]:
            with self.app.test_request_context('/token/init', method='POST',
                                               data={"type": "hotp",
                                                     "otpkey": self.otpkey,
                                                     "serial": serial,
                                                     "realm": self.realm1},
                                               headers={'Authorization':
                                                            self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)

        # list tokens of realm1
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "tokenrealm": self.realm1}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            count = result.get("value").get("count")
            next = result.get("value").get("next")
            prev = result.get("value").get("prev")
            self.assertTrue(len(tokenlist) == 2, res.data)
            self.assertTrue(count == 2, count)

        # list tokens, that look a bit like realm1
        search_realm = self.realm1[:-1] + "*"
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({
                                               "tokenrealm": search_realm}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            tokenlist = result.get("value").get("tokens")
            count = result.get("value").get("count")
            next = result.get("value").get("next")
            prev = result.get("value").get("prev")
            self.assertTrue(len(tokenlist) == 2, res.data)
            self.assertTrue(count == 2, count)

    def test_04_assign_unassign_token(self):
        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "realm": self.realm1,
                                                 "serial": "S1",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") is True, result)

        # Assign the same token to another user will fail
        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"user": "shadow",
                                                 "realm": self.realm1,
                                                 "serial": "S1"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            error = result.get("error")
#            self.assertEqual(error.get("message"),
#                             "ERR1103: Token already assigned to user "
#                             "User(login='cornelius', realm='realm1', "
#                             "resolver='resolver1')")
            self.assertRegexpMatches(error.get('message'),
                                     r"ERR1103: Token already assigned to user "
                                     r"User\(login=u?'cornelius', "
                                     r"realm=u?'realm1', resolver=u?'resolver1'\)")

        # Now the user tries to assign a foreign token
        with self.app.test_request_context('/auth',
                                           method='POST',
                                           data={"username":
                                                     "selfservice@realm1",
                                                 "password": "test"}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("status"), res.data)
            # In self.at_user we store the user token
            self.at_user = result.get("value").get("token")

        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"serial": "S1"},
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            error = result.get("error")
            self.assertEqual(error.get("message"), "ERR1103: Token already assigned to another user.")

        # Now unassign the token
        with self.app.test_request_context('/token/unassign',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "realm": self.realm1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # Assign the same token to another user will success
        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"user": "shadow",
                                                 "realm": self.realm1,
                                                 "serial": "S1"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") is True, result)

        # Unassign without any arguments will raise a ParameterError
        with self.app.test_request_context('/token/unassign',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        # assign S3 and S4 to cornelius
        for serial in ("S3", "S4"):
            with self.app.test_request_context('/token/assign',
                                               method='POST',
                                               data={"user": "cornelius",
                                                     "realm": self.realm1,
                                                     "serial": serial,
                                                     "pin": "test"},
                                               headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertEqual(res.status_code, 200)

        # Check that it worked
        user = User('cornelius', self.realm1)
        tokens = get_tokens_from_serial_or_user(None, user)
        self.assertEqual({t.token.serial for t in tokens}, {"S3", "S4"})

        # unassign all
        with self.app.test_request_context('/token/unassign',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "realm": self.realm1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200)
            result = res.json.get("result")
            self.assertTrue(result["value"], 2)

        # Check that it worked
        tokens = get_tokens_from_serial_or_user(None, user)
        self.assertEqual(tokens, [])

    def test_05_delete_token(self):
        self._create_temp_token("DToken")

        with self.app.test_request_context('/token/DToken',
                                           method='DELETE',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # Try to remove token, that does not exist raises a 404
        with self.app.test_request_context('/token/DToken',
                                           method='DELETE',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            result = res.json.get("result")
            self.assertEqual(res.status_code, 404)
            self.assertFalse(result.get("status"))

    def test_06_disable_enable_token(self):
        self._create_temp_token("EToken")

        # try to disable a token with no parameters
        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        # disable an assigned token
        r = assign_token("EToken", User("hans", self.realm1))
        self.assertTrue(r)
        with self.app.test_request_context('/token/disable/EToken',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # Check for the disabled token in the audit log, that also the user object is added
        with self.app.test_request_context('/audit/',
                                           method='GET',
                                           data={'action': "*disable*", "serial": "EToken"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200, res)
            jres = res.json
            self.assertEqual(jres['result']['value']['auditdata'][0]['user'], "hans")

        # disable a disabled token will not count, so the value will be 0
        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={"serial": "EToken"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 0, result)

        # enable the token again
        with self.app.test_request_context('/token/enable/EToken',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # try to enable an already enabled token returns value=0
        with self.app.test_request_context('/token/enable',
                                           method='POST',
                                           data={"serial": "EToken"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 0, result)

    def test_07_reset_failcounter(self):
        serial = "RToken"
        self._create_temp_token(serial)

        # Set the failcounter to 12
        tokenobject_list = get_tokens(serial=serial)
        tokenobject_list[0].token.failcount = 12
        tokenobject_list[0].save()

        # reset the failcounter
        with self.app.test_request_context('/token/reset/RToken',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # test the failcount
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           query_string=urlencode({"serial":
                                                                       serial}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(value.get("count") == 1, value)
            self.assertTrue(token.get("failcount") == 0, token)

        # reset failcount again, will again return value=1
        with self.app.test_request_context('/token/reset',
                                           method='POST',
                                           data={"serial": serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

    def test_07_resync(self):

        with self.app.test_request_context('/token/init', method="POST",
                                           data={"serial": "Resync01",
                                                 "otpkey": self.otpkey},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

            """
                                             Truncated
               Count    Hexadecimal    Decimal        HOTP
               0        4c93cf18       1284755224     755224
               1        41397eea       1094287082     287082
               2         82fef30        137359152     359152
               3        66ef7655       1726969429     969429
               4        61c5938a       1640338314     338314
               5        33c083d4        868254676     254676
               6        7256c032       1918287922     287922
               7         4e5b397         82162583     162583
               8        2823443f        673399871     399871
               9        2679dc69        645520489     520489
            """

        # Resync does not work with NON-consecutive values
        with self.app.test_request_context('/token/resync/Resync01',
                                            method="POST",
                                            data={"otp1": 287082,
                                                  "otp2": 969429},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") is False, result)

        # check that we have a failed request in the audit log
        with self.app.test_request_context('/audit/',
                                           method='GET',
                                           data={'action': "POST /token/resync/<serial>",
                                                 'serial': 'Resync01',
                                                 'success': '0'},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200, res)
            self.assertEqual(len(res.json['result']['value']['auditdata']), 1, res.json)
            self.assertEqual(res.json['result']['value']['auditdata'][0]['success'], 0, res.json)

        # Successful resync with consecutive values
        with self.app.test_request_context('/token/resync',
                                            method="POST",
                                            data={"serial": "Resync01",
                                                  "otp1": 359152,
                                                  "otp2": 969429},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") is True, result)

        # Check for a successful request in the audit log
        with self.app.test_request_context('/audit/',
                                           method='GET',
                                           data={'action': "POST /token/resync",
                                                 'serial': 'Resync01',
                                                 'success': '1'},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200, res)
            self.assertEqual(len(res.json['result']['value']['auditdata']), 1, res.json)
            self.assertEqual(res.json['result']['value']['auditdata'][0]['success'], 1, res.json)

        # Get the OTP token and inspect the counter
        with self.app.test_request_context('/token/',
                                            method="GET",
                                            query_string=urlencode({"serial": "Resync01"}),
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(token.get("count") == 4, result)

        # Authenticate a user
        with self.app.test_request_context('/auth',
                                           method='POST',
                                           data={"username":
                                                     "selfservice@realm1",
                                                 "password": "test"}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("status"), res.data)
            # In self.at_user we store the user token
            self.at_user = result.get("value").get("token")

        # The user fails to resync the token, since it does not belong to him
        with self.app.test_request_context('/token/resync',
                                            method="POST",
                                            data={"serial": "Resync01",
                                                  "otp1": 254676,
                                                  "otp2": 287922},
                                            headers={'Authorization':
                                                         self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            self.assertFalse(result["status"])

        # assign the token to the user selfservice@realm1.
        with self.app.test_request_context('/token/assign',
                                            method="POST",
                                            data={"serial": "Resync01",
                                                  "user": "selfservice@realm1"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertEqual(result.get("value"), True)

        # let the user resync the token
        with self.app.test_request_context('/token/resync',
                                            method="POST",
                                            data={"serial": "Resync01",
                                                  "otp1": 254676,
                                                  "otp2": 287922},
                                            headers={'Authorization':
                                                         self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") is True, result)


    def test_08_setpin(self):
        self._create_temp_token("PToken")
        # Set one PIN of the token
        with self.app.test_request_context('/token/setpin',
                                            method="POST",
                                            data={"serial": "PToken",
                                                  "userpin": "test"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # Set both PINs of the token
        with self.app.test_request_context('/token/setpin/PToken',
                                            method="POST",
                                            data={"userpin": "test",
                                                  "sopin": "topsecret"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 2, result)

        # set a pin
        with self.app.test_request_context('/token/setpin/PToken',
                                            method="POST",
                                            data={"otppin": "test"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # set an empty pin
        with self.app.test_request_context('/token/setpin/PToken',
                                            method="POST",
                                            data={"otppin": ""},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

    def test_09_set_token_attributes(self):
        self._create_temp_token("SET001")
        # Set some things
        with self.app.test_request_context('/token/setpin',
                                            method="POST",
                                            data={"serial": "SET001",
                                                  "otppin": "test"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)


        # Set all other values
        with self.app.test_request_context('/token/set/SET001',
                                            method="POST",
                                            data={"count_auth_max": 17,
                                                  "count_auth_success_max": 8,
                                                  "hashlib": "sha2",
                                                  "count_window": 11,
                                                  "sync_window": 999,
                                                  "max_failcount": 15,
                                                  "description": "Some Token",
                                                  "validity_period_start":
                                                      "2014-05-22T22:00+0200",
                                                  "validity_period_end":
                                                      "2014-05-22T23:00+0200"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 9, result)

        # check the values
        with self.app.test_request_context('/token/',
                                           method="GET",
                                           query_string=urlencode(
                                                   {"serial": "SET001"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(value.get("count") == 1, result)

            self.assertTrue(token.get("count_window") == 11, token)
            self.assertTrue(token.get("sync_window") == 999, token)
            self.assertTrue(token.get("maxfail") == 15, token)
            self.assertTrue(token.get("description") == "Some Token", token)
            tokeninfo = token.get("info")
            self.assertTrue(tokeninfo.get("hashlib") == "sha2", tokeninfo)
            self.assertTrue(tokeninfo.get("count_auth_max") == "17",
                            tokeninfo)
            self.assertTrue(tokeninfo.get("count_auth_success_max") == "8",
                            tokeninfo)
            self.assertEqual(tokeninfo.get("validity_period_start"),
                             "2014-05-22T22:00+0200")
            self.assertEqual(tokeninfo.get("validity_period_end"),
                             "2014-05-22T23:00+0200")

        # check for broken validity dates
        with self.app.test_request_context('/token/set/SET001',
                                           method="POST",
                                           data={"validity_period_start": "unknown"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 400, res)
            result = res.json.get("result")
            self.assertEqual(result['error']['code'], 301, result)
            self.assertEqual(result['error']['message'],
                             "ERR301: Could not parse validity period start date!",
                             result)

    def test_10_set_token_realms(self):
        self._create_temp_token("REALM001")

        with self.app.test_request_context('/token/realm/REALM001',
                                            method="POST",
                                            data={"realms": "realm1, realm2"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value is True, result)

        with self.app.test_request_context('/token/',
                                            method="GET",
                                            query_string=urlencode({"serial": "REALM001"}),
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(token.get("realms") == ["realm1"], token)

    def test_11_load_tokens(self):
        # Set dummy policy to verify faulty behaviour with #2209
        set_policy("dumm01", scope=SCOPE.USER, action=ACTION.DISABLE)
        # Load OATH CSV
        with self.app.test_request_context('/token/load/import.oath',
                                            method="POST",
                                            data={"type": "oathcsv",
                                                  "tokenrealms": self.realm1,
                                                  "file": (IMPORTFILE,
                                                           "import.oath")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 3, result)
        # check for a successful audit entry
        entry = self.find_most_recent_audit_entry(action='*/token/load/*')
        self.assertEqual(entry['success'], 1, entry)
        delete_policy("dumm01")

        # Load GPG encrypted OATH CSV
        with self.app.test_request_context('/token/load/import.oath.asc',
                                           method="POST",
                                           data={"type": "oathcsv",
                                                 "file": (IMPORTFILE_GPG,
                                                          "import.oath.asc")},
                                           headers={
                                               'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 3, result)

        # Load yubico.csv
        with self.app.test_request_context('/token/load/yubico.csv',
                                            method="POST",
                                            data={"type": "yubikeycsv",
                                                  "tokenrealms": self.realm1,
                                                  "file": (YUBICOFILE,
                                                           "yubico.csv")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 3, result)

        # check if the token was put into self.realm1
        tokenobject_list = get_tokens(serial="UBOM508327_X")
        self.assertEqual(len(tokenobject_list), 1)
        token = tokenobject_list[0]
        self.assertEqual(token.token.realm_list[0].realm.name, self.realm1)

        # Try to load empty file
        with self.app.test_request_context('/token/load/empty.oath',
                                            method="POST",
                                            data={"type": "oathcsv",
                                                  "file": (IMPORTFILE2,
                                                           "empty.oath")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
        # check for a failed audit entry
        entry = self.find_most_recent_audit_entry(action='*/token/load/*')
        self.assertEqual(entry['success'], 0, entry)

        # Try to load unknown file type
        with self.app.test_request_context('/token/load/import.oath',
                                            method="POST",
                                            data={"type": "unknown",
                                                  "file": (IMPORTFILE,
                                                           "import.oath")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        # Load PSKC file, encrypted PSK
        with self.app.test_request_context('/token/load/pskc-aes.xml',
                                            method="POST",
                                            data={"type": "pskc",
                                                  "psk": PSK_HEX,
                                                  "file": (IMPORTPSKC,
                                                           "pskc-aes.xml")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 1, result)

        # Load PSKC file, encrypted Password
        with self.app.test_request_context('/token/load/pskc-password.xml',
                                            method="POST",
                                            data={"type": "pskc",
                                                  "password": "qwerty",
                                                  "file": (IMPORTPSKC_PASS,
                                                           "pskc-password.xml")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 1, result)

    def test_11_load_tokens_tokenhandler(self):

        # create a new event to disable tokens after import
        r = set_event("token_disable", ["token_load"], "Token",
                      "disable", position="post")
        events = EventConfiguration()
        event_id = [event['id'] for event in events.events if event['name'] == 'token_disable'][0]

        # Load yubico.csv
        with self.app.test_request_context('/token/load/yubico.csv',
                                            method="POST",
                                            data={"type": "yubikeycsv",
                                                  "tokenrealms": self.realm1,
                                                  "file": (YUBICOFILE_LONG,
                                                           "yubico.csv")},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 100, result)

        # check if imported tokens were disabled by event handler
        tokenobject_list = get_tokens(serial_wildcard="UBOM*", active=False)
        self.assertEqual(len(tokenobject_list), 100)

        # remove tokens
        for tok in tokenobject_list:
            remove_token(serial=tok.token.serial)
        # remove event
        delete_event(event_id)

    def test_11_load_tokens_only_to_specific_realm(self):
        # Load token to a realm
        def _clean_up_tokens():
            remove_token("token01")
            remove_token("token02")
            remove_token("token03")

        _clean_up_tokens()
        with self.app.test_request_context('/token/load/import.oath',
                                           method="POST",
                                           data={"type": "oathcsv",
                                                 "tokenrealms": self.realm1,
                                                 "file": (IMPORTFILE,
                                                          "import.oath")},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 3, result)
        # Now check, if the tokens are in the realm
        from privacyidea.lib.token import get_realms_of_token
        r = get_realms_of_token("token01")
        self.assertIn(self.realm1, r)

        # Now set a policy, that allows the admin to upload the tokens into this realm
        set_policy(name="tokupload", scope=SCOPE.ADMIN, action=ACTION.IMPORT, realm=self.realm1,
                   adminuser="testadmin")
        _clean_up_tokens()
        with self.app.test_request_context('/token/load/import.oath',
                                           method="POST",
                                           data={"type": "oathcsv",
                                                 "tokenrealms": self.realm1,
                                                 "file": (IMPORTFILE,
                                                          "import.oath")},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")['n_imported']
            self.assertTrue(value == 3, result)
        # Now check, if the tokens are in the realm
        r = get_realms_of_token("token01")
        self.assertIn(self.realm1, r)

        # Now define a policy, that allows the user to upload tokens to some other realm
        set_policy(name="tokupload", scope=SCOPE.ADMIN, action=ACTION.IMPORT, realm="otherrealm",
                   adminuser="testadmin")
        _clean_up_tokens()
        with self.app.test_request_context('/token/load/import.oath',
                                           method="POST",
                                           data={"type": "oathcsv",
                                                 "tokenrealms": self.realm1,
                                                 "file": (IMPORTFILE,
                                                          "import.oath")},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 403, res)
            result = res.json.get("result")
            self.assertFalse(result.get("status"))
            self.assertEqual(u"Admin actions are defined, but you are not allowed to upload token files.",
                             result.get("error").get("message"))

        delete_policy("tokupload")

    def test_12_copy_token(self):
        self._create_temp_token("FROM001")
        self._create_temp_token("TO001")
        with self.app.test_request_context('/token/assign',
                                            method="POST",
                                            data={"serial": "FROM001",
                                                  "user": "cornelius",
                                                  "realm": self.realm1},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value is True, result)

        with self.app.test_request_context('/token/setpin',
                                            method="POST",
                                            data={"serial": "FROM001",
                                                  "otppin": "test"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value == 1, result)

        # copy the PIN
        with self.app.test_request_context('/token/copypin',
                                            method="POST",
                                            data={"from": "FROM001",
                                                  "to": "TO001"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value is True, result)

        # copy the user
        with self.app.test_request_context('/token/copyuser',
                                            method="POST",
                                            data={"from": "FROM001",
                                                  "to": "TO001"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value is True, result)

        # check in the database
        tokenobject_list = get_tokens(serial="TO001")
        token = tokenobject_list[0]
        # check the user
        self.assertEqual(token.token.first_owner.user_id, "1000")
        # check if the TO001 has a pin
        self.assertTrue(token.token.pin_hash.startswith("$argon2"))

    def test_13_lost_token(self):
        self._create_temp_token("LOST001")

        # call lost token for a token, that is not assigned.
        # THis will create an exception
        with self.app.test_request_context('/token/lost/LOST001',
                                            method="POST",
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        # assign the token
        with self.app.test_request_context('/token/assign',
                                            method="POST",
                                            data={"serial": "LOST001",
                                                  "user": "cornelius",
                                                  "realm": self.realm1},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue(value is True, result)

        with self.app.test_request_context('/token/lost/LOST001',
                                            method="POST",
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertTrue("end_date" in value, value)
            self.assertTrue(value.get("serial") == "lostLOST001", value)

        # check if the user cornelius now owns the token lostLOST001
        tokenobject_list = get_tokens(user=User("cornelius",
                                                realm=self.realm1),
                                      serial="lostLOST001")
        self.assertTrue(len(tokenobject_list) == 1, tokenobject_list)

    def test_14_get_serial_by_otp(self):
        self._create_temp_token("T1")
        self._create_temp_token("T2")
        self._create_temp_token("T3")
        init_token({"serial": "GETSERIAL",
                    "otpkey": OTPKEY})

        # Only get the number of tokens, which would be searched: 28
        with self.app.test_request_context('/token/getserial/162583?count=1',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 25)
            self.assertEqual(value.get("serial"), None)

        # multiple tokens are matching!
        with self.app.test_request_context('/token/getserial/162583',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

        init_token({"serial": "GETSERIAL2",
                    "otpkey": OTPKEY2})

        with self.app.test_request_context('/token/getserial/316522',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("serial"), "GETSERIAL2")

        # If one OTP values was found, it can not be used again
        with self.app.test_request_context('/token/getserial/316522',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("serial"), None)


        # Will not find an assigned token
        with self.app.test_request_context('/token/getserial/413789'
                                           '?assigned=1',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertNotEqual(value.get("serial"), "GETSERIAL2")

        # Will find a substr
        with self.app.test_request_context('/token/getserial/413789'
                                           '?unassigned=1&string=SERIAL',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("serial"), "GETSERIAL2")

    def test_15_registration_code(self):
        # Test the registration code token
        # create the registration code token
        with self.app.test_request_context('/token/init',
                                           data={"type": "registration",
                                                 "serial": "reg1",
                                                 "user": "cornelius"},
                                           method="POST",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))
            detail = res.json.get("detail")
            registrationcode = detail.get("registrationcode")

        # check password
        with self.app.test_request_context('/validate/check',
                                           data={"user": "cornelius",
                                                 "pass": registrationcode},
                                           method="POST"):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))

        # check password again. THe second time it will fail, since the token
        # does not exist anymore.
        with self.app.test_request_context('/validate/check',
                                           data={"user": "cornelius",
                                                 "pass": registrationcode},
                                           method="POST"):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertFalse(result.get("value"))

    def test_16_totp_timestep(self):
        # Test the timestep of the token
        for timestep in ["30", "60"]:
            with self.app.test_request_context('/token/init',
                                               data={"type": "totp",
                                                     "serial": "totp{0!s}".format(
                                                             timestep),
                                                     "timeStep": timestep,
                                                     "genkey": "1"},
                                               method="POST",
                                               headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)
                result = res.json.get("result")
                self.assertTrue(result.get("value"))
                detail = res.json.get("detail")

            token = get_tokens(serial="totp{0!s}".format(timestep))[0]
            self.assertEqual(token.timestep, int(timestep))

    def test_17_enroll_certificate(self):
        self.setUp_user_realms()
        cwd = os.getcwd()
        # setup ca connector
        r = save_caconnector({"cakey": CAKEY,
                              "cacert": CACERT,
                              "type": "local",
                              "caconnector": "localCA",
                              "openssl.cnf": OPENSSLCNF,
                              "CSRDir": "",
                              "CertificateDir": "",
                              "WorkingDir": cwd + "/" + WORKINGDIR})

        # Enroll a certificate token with a CSR
        with self.app.test_request_context('/token/init',
                                           data={"type": "certificate",
                                                 "request": REQUEST,
                                                 "ca": "localCA"},
                                           method="POST",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))
            detail = res.json.get("detail")
            certificate = detail.get("certificate")
            self.assertTrue("-----BEGIN CERTIFICATE-----" in certificate)

        # Enroll a certificate token, also generating a private key
        with self.app.test_request_context('/token/init',
                                           data={"type": "certificate",
                                                 "genkey": "1",
                                                 "user": "cornelius",
                                                 "realm": self.realm1,
                                                 "ca": "localCA"},
                                           method="POST",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = json.loads(res.data.decode('utf8')).get("result")
            self.assertTrue(result.get("value"))
            detail = json.loads(res.data.decode('utf8')).get("detail")
            self.assertIn("pkcs12", detail)

        # List tokens
        with self.app.test_request_context('/token/?type=certificate',
                                           method="GET",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = json.loads(res.data.decode('utf8')).get("result")
            self.assertEqual(len(result["value"]["tokens"]), 2)

        # Finally we try to enroll a certificate with an attestation certificate required:
        from privacyidea.lib.tokens.certificatetoken import ACTION, REQUIRE_ACTIONS
        set_policy(name="pol1",
                   scope=SCOPE.ENROLL,
                   action="{0!s}={1!s}".format(ACTION.REQUIRE_ATTESTATION, REQUIRE_ACTIONS.REQUIRE_AND_VERIFY))
        with self.app.test_request_context('/token/init',
                                           data={"type": "certificate",
                                                 "request": REQUEST,
                                                 "ca": "localCA"},
                                           method="POST",
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 403, res)
            result = res.json.get("result")
            self.assertFalse(result.get("status"))
            self.assertEqual(result.get("error").get("message"),
                             "A policy requires that you provide an attestation certificate.")

        delete_policy("pol1")


    def test_18_revoke_token(self):
        self._create_temp_token("RevToken")

        # revoke token
        with self.app.test_request_context('/token/revoke/RevToken',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value") == 1, result)

        # Try to enable the revoked token
        with self.app.test_request_context('/token/enable/RevToken',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)

    def test_19_get_challenges(self):
        set_policy("chalresp", scope=SCOPE.AUTHZ,
        action="{0!s}=hotp".format(ACTION.CHALLENGERESPONSE))
        token = init_token({"genkey": 1, "serial": "CHAL1", "pin": "pin"})
        serial = token.token.serial
        r = check_serial_pass(serial, "pin")
        # The OTP PIN is correct
        self.assertEqual(r[0], False)
        self.assertEqual(r[1].get("message"), _("please enter otp: "))
        transaction_id = r[1].get("transaction_id")

        with self.app.test_request_context('/token/challenges/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 1)
            challenges = value.get("challenges")
            self.assertEqual(challenges[0].get("transaction_id"),
                             transaction_id)

        # There is one challenge for token CHAL1
        with self.app.test_request_context('/token/challenges/CHAL1',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 1)
            challenges = value.get("challenges")
            self.assertEqual(challenges[0].get("transaction_id"),
                             transaction_id)

        # There is no challenge for token CHAL2
        with self.app.test_request_context('/token/challenges/CHAL2',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 0)

        # create a second challenge and a third cahllenge
        r = check_serial_pass(serial, "pin")
        r = check_serial_pass(serial, "pin")
        transaction_ids = []
        with self.app.test_request_context('/token/challenges/',
                                           method='GET',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 3)
            challenges = value.get("challenges")
            for challenge in challenges:
                # Fill the list of all transaction_ids
                transaction_ids.append(challenge.get("transaction_id"))

        # Now we only ask for the first transation id. This should return only ONE challenge
        with self.app.test_request_context('/token/challenges/',
                                            data={"transaction_id": transaction_ids[0]},
                                            method='GET',
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            self.assertEqual(value.get("count"), 1)
            challenges = value.get("challenges")
            self.assertEqual(challenges[0].get("transaction_id"), transaction_ids[0])

        delete_policy("chalresp")

    def test_20_init_yubikey(self):
        # save yubikey.prefix
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={
                                               "type": "yubikey",
                                               "serial": "yk1",
                                               "otpkey": self.otpkey,
                                               "yubikey.prefix": "vv123456"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("status"), result)
            self.assertTrue(result.get("value"), result)

        tokens = get_tokens(serial="yk1")
        self.assertEqual(tokens[0].get_tokeninfo("yubikey.prefix"), "vv123456")

    def test_21_time_policies(self):
        # Here we test, if an admin policy does not match in time,
        # it still used to evaluate, that admin policies are defined at all
        set_policy(name="admin_time", scope=SCOPE.ADMIN,
                   action="enrollSPASS",
                   time="Sun: 0-23:59")
        tn = datetime.datetime.now()
        dow = tn.isoweekday()
        P = PolicyClass()
        all_admin_policies = P.list_policies()
        self.assertEqual(len(all_admin_policies), 1)
        self.assertEqual(len(P.policies), 1)

        if dow in [7]:
            # Only on sunday the admin is allowed to enroll a SPASS token. On
            # all other days this will raise an exception
            with self.app.test_request_context(
                    '/token/init',
                    method='POST',
                    data={"type": "spass"},
                    headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)
        else:
            # On other days enrolling a spass token will trigger an error,
            # since the admin has no rights at all. Only on sunday.
            with self.app.test_request_context(
                    '/token/init',
                    method='POST',
                    data={"type": "spass"},
                    headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 403, res)

        delete_policy("admin_time")

    def test_22_delete_token_in_foreign_realm(self):
        # Check if a realm admin can not delete a token in another realm
        # Admin is only allowed to delete tokens in "testrealm"
        set_policy("deleteToken", scope=SCOPE.ADMIN,
                   action="delete",
                   user="testadmin",
                   realm="testrealm"
                   )
        r = init_token({"type": "SPASS", "serial": "SP001"},
                       user=User("cornelius", self.realm1))

        # Now testadmin tries to delete a token from realm1, which he can not
        #  access.
        with self.app.test_request_context('/token/SP001',
                                           method='DELETE',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 403, res)

        remove_token("SP001")
        delete_policy("deleteToken")

    def test_23_change_pin_on_first_use(self):

        set_policy("firstuse", scope=SCOPE.ENROLL,
                   action=ACTION.CHANGE_PIN_FIRST_USE)

        current_time = datetime.datetime.now(tzlocal())
        with mock.patch('privacyidea.lib.tokenclass.datetime') as mock_dt:
            mock_dt.now.return_value = current_time
            with self.app.test_request_context('/token/init',
                                               method='POST',
                                               data={"genkey": 1,
                                                     "pin": "123456"},
                                               headers={'Authorization': self.at}):
                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)
                detail = res.json.get("detail")

                serial = detail.get("serial")
                token = get_tokens(serial=serial)[0]
                ti = token.get_tokeninfo("next_pin_change")
                self.assertEqual(ti, current_time.strftime(DATE_FORMAT))

        # If the administrator sets a PIN of the user, the next_pin_change
        # must also be created!

        token = init_token({"serial": "SP001", "type": "spass", "pin":
            "123456"})
        ti = token.get_tokeninfo("next_pin_change")
        self.assertEqual(ti, None)
        # Now we set the PIN
        current_time = datetime.datetime.now(tzlocal())
        with mock.patch('privacyidea.lib.tokenclass.datetime') as mock_dt:
            mock_dt.now.return_value = current_time
            with self.app.test_request_context('/token/setpin/SP001',
                                               method='POST',
                                               data={"otppin": "1234"},
                                               headers={'Authorization': self.at}):

                res = self.app.full_dispatch_request()
                self.assertTrue(res.status_code == 200, res)

                serial = "SP001"
                token = get_tokens(serial=serial)[0]
                ti = token.get_tokeninfo("next_pin_change")
                self.assertEqual(ti, current_time.strftime(DATE_FORMAT))

        delete_policy("firstuse")

    def test_24_modify_tokeninfo(self):
        self._create_temp_token("INF001")
        # Set two tokeninfo values
        with self.app.test_request_context('/token/info/INF001/key1',
                                            method="POST",
                                            data={"value": "value 1"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"), result)
        with self.app.test_request_context('/token/info/INF001/key2',
                                            method="POST",
                                            data={"value": "value 2"},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"), result)

        with self.app.test_request_context('/token/',
                                           method="GET",
                                           query_string=urlencode(
                                                   {"serial": "INF001"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(value.get("count") == 1, result)

            tokeninfo = token.get("info")
            test_dict = {'key1': 'value 1', 'key2': 'value 2'}
            try:
                self.assertTrue(test_dict.viewitems() <= tokeninfo.viewitems())
            except AttributeError:
                self.assertTrue(test_dict.items() <= tokeninfo.items())

        # Overwrite an existing tokeninfo value
        with self.app.test_request_context('/token/info/INF001/key1',
                                            method="POST",
                                            data={"value": 'value 1 new'},
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"), result)

        with self.app.test_request_context('/token/',
                                           method="GET",
                                           query_string=urlencode(
                                                   {"serial": "INF001"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(value.get("count") == 1, result)

            tokeninfo = token.get("info")
            test_dict = {'key1': 'value 1 new', 'key2': 'value 2'}
            try:
                self.assertTrue(test_dict.viewitems() <= tokeninfo.viewitems())
            except AttributeError:
                self.assertTrue(test_dict.items() <= tokeninfo.items())

        # Delete an existing tokeninfo value
        with self.app.test_request_context('/token/info/INF001/key1',
                                           method="DELETE",
                                           headers={'Authorization': self.at}):
           res = self.app.full_dispatch_request()
           self.assertTrue(res.status_code == 200, res)
           result = res.json.get("result")
           self.assertTrue(result.get("value"), result)

        # Delete a non-existing tokeninfo value
        with self.app.test_request_context('/token/info/INF001/key1',
                                            method="DELETE",
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"), result)

        # Try to delete with an unknown serial
        with self.app.test_request_context('/token/info/UNKNOWN/key1',
                                            method="DELETE",
                                            headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            self.assertFalse(result.get("status"))

        # Check that the tokeninfo is correct
        with self.app.test_request_context('/token/',
                                           method="GET",
                                           query_string=urlencode(
                                               {"serial": "INF001"}),
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            value = result.get("value")
            token = value.get("tokens")[0]
            self.assertTrue(value.get("count") == 1, result)

            tokeninfo = token.get("info")
            try:
                self.assertTrue({'key2': 'value 2'}.viewitems() <= tokeninfo.viewitems())
            except AttributeError:
                self.assertTrue({'key2': 'value 2'}.items() <= tokeninfo.items())
            self.assertNotIn('key1', tokeninfo)

    def test_25_user_init_defaults(self):
        self.setUp_user_realms()
        self.authenticate_selfservice_user()
        # Now this user is authenticated as selfservice@realm1

        # first test with system configuration
        set_privacyidea_config('totp.hashlib', 'sha512')
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={
                                               "type": "totp",
                                               "genkey": 1,
                                               "user": "selfservice",
                                               "realm": "realm1"},
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            self.assertTrue(res.json.get('result').get("value"))
            detail = res.json.get("detail")
            googleurl = detail.get("googleurl")
            # TODO: The google URL states no hashlib (which means sha1) but the
            #       actual hashlib is sha512 since no hashlib parameter was
            #       send in the request.
            #       This is wrong and needs to be fixed in hotptoken.py:253
            self.assertFalse("sha1" in googleurl.get("value"))
            serial = detail.get("serial")
            token = get_tokens(serial=serial)[0]
            self.assertEqual(token.hashlib, "sha512")
            self.assertEqual(token.timestep, 30)
            self.assertEqual(token.token.otplen, 6)
            remove_token(serial)

        # Now create policy for sha256, overwriting the system config
        set_policy(name="init_details",
                   scope=SCOPE.USER,
                   action="totp_otplen=8,totp_hashlib=sha256,"
                          "totp_timestep=60,enrollTOTP")

        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={
                                               "type": "totp",
                                               "totp.hashlib": "sha1",
                                               "hashlib": "sha1",
                                               "genkey": 1,
                                               "user": "selfservice",
                                               "realm": "realm1"},
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))
            detail = res.json.get("detail")
            googleurl = detail.get("googleurl")
            self.assertTrue("sha256" in googleurl.get("value"))
            serial = detail.get("serial")
            token = get_tokens(serial=serial)[0]
            self.assertEqual(token.hashlib, "sha256")
            self.assertEqual(token.token.otplen, 8)

        delete_policy("init_details")
        remove_token(serial)

        # Set OTP len using the system wide default
        set_privacyidea_config("DefaultOtpLen", 8)
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={
                                               "type": "totp",
                                               "totp.hashlib": "sha1",
                                               "hashlib": "sha1",
                                               "genkey": 1,
                                               "user": "selfservice",
                                               "realm": "realm1"},
                                           headers={'Authorization':
                                                        self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))
            detail = res.json.get("detail")
            serial = detail.get("serial")
            token = get_tokens(serial=serial)[0]
            self.assertEqual(token.token.otplen, 8)

        remove_token(serial)

        # override the DefaultOtpLen
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={
                                               "type": "totp",
                                               "otplen": 6,
                                               "totp.hashlib": "sha1",
                                               "hashlib": "sha1",
                                               "genkey": 1,
                                               "user": "selfservice",
                                               "realm": "realm1"},
                                           headers={'Authorization':
                                                        self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("value"))
            detail = res.json.get("detail")
            serial = detail.get("serial")
            token = get_tokens(serial=serial)[0]
            self.assertEqual(token.token.otplen, 6)

        remove_token(serial)
        delete_privacyidea_config("DefaultOtpLen")

    def test_26_supply_key_size(self):
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"type": "HOTP",
                                                 "genkey": '1',
                                                 "pin": "1234",
                                                 "user": "cornelius",
                                                 "keysize": "42",
                                                 "realm": self.realm1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            data = res.json
            self.assertTrue(res.status_code == 200, res)
            result = data.get("result")
            detail = data.get("detail")
            self.assertTrue(result.get("status"), result)
            self.assertTrue(result.get("value"), result)
            self.assertTrue("value" in detail.get("googleurl"), detail)
            serial = detail.get("serial")
            self.assertTrue("OATH" in serial, detail)
            seed_url = detail.get("otpkey").get("value")
            self.assertEqual(seed_url[:len('seed://')], 'seed://')
            seed = seed_url[len('seed://'):]
            self.assertEqual(len(codecs.decode(seed, 'hex')), 42)
        remove_token(serial)

    def test_27_fail_to_assign_empty_serial(self):
        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "realm": self.realm1,
                                                 "serial": "",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            self.assertEqual(result.get("status"), False)
            self.assertEqual(result.get("error").get("code"), 905)

    def test_28_enroll_app_with_image_url(self):
        set_policy("imgurl", scope=SCOPE.ENROLL,
                   action="{0!s}=https://example.com/img.png".format(ACTION.APPIMAGEURL))
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "genkey": "1",
                                                 "realm": self.realm1,
                                                 "serial": "goog1",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            self.assertTrue(result.get("status"))
            self.assertTrue(result.get("value"))
            self.assertTrue(u'image=https%3A//example.com/img.png' in detail.get("googleurl").get("value"),
                            detail.get("googleurl"))

        remove_token("goog1")
        delete_policy("imgurl")

    def test_29_user_set_description(self):
        self.authenticate_selfservice_user()
        # create a token for the user
        r = init_token({"serial": "SETDESC01",
                        "otpkey": self.otpkey},
                       user=User("selfservice", "realm1"))
        self.assertTrue(r)

        # create a token, that does not belong to the user
        r = init_token({"serial": "SETDESC02",
                        "otpkey": self.otpkey})
        self.assertTrue(r)

        # policy: allow user to set description
        set_policy(name="SETDESCPOL", scope=SCOPE.USER,
                   action=ACTION.SETDESCRIPTION)

        # successful set description on own token
        with self.app.test_request_context('/token/description/SETDESC01',
                                           method='POST',
                                           data={"description": "New Token"},
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("status"))
            self.assertEqual(result.get("value"), 1)

        # check the description of the token
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           data={"serial": "SETDESC01"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertTrue(result.get("status"))
            self.assertEqual(result.get("value").get("tokens")[0].get("description"),
                             "New Token")

        # fail to set description on foreign token
        with self.app.test_request_context('/token/description',
                                           method='POST',
                                           data={"serial": "SETDESC02",
                                                 "description": "new token"},
                                           headers={'Authorization': self.at_user}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 404, res)
            result = res.json.get("result")
            self.assertFalse(result.get("status"))
            self.assertEqual(result.get("error").get("message"),
                             u"The requested token could not be found.")

        # cleanup
        delete_policy("SETDESCPOL")
        remove_token("SETDESC01")
        remove_token("SETDESC02")

    def test_30_force_app_pin(self):
        set_policy("app_pin", scope=SCOPE.ENROLL,
                   action={"hotp_" + ACTION.FORCE_APP_PIN: True,
                           "totp_" + ACTION.FORCE_APP_PIN: True})
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "genkey": "1",
                                                 "realm": self.realm1,
                                                 "serial": "goog2",
                                                 "type": 'TOTP',
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json["result"]
            detail = res.json["detail"]
            self.assertTrue(result.get("status"))
            self.assertTrue(result.get("value"))
            self.assertTrue(u'pin=True' in detail.get("googleurl").get("value"),
                            detail.get("googleurl"))

        remove_token("goog2")
        delete_policy('app_pin')

    def test_31_invalid_serial(self):
        # Run a test with an invalid serial
        with self.app.test_request_context('/token/init',
                                           method='POST',
                                           data={"serial": "invalid/character",
                                                 "genkey": 1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            self.assertTrue("Invalid serial number" in result.get("error").get("message"))

    def test_32_set_random_pin(self):
        t = init_token({"genkey": 1})
        self.assertEqual(t.token.tokentype, "hotp")

        # We get an error, if there is no policy
        with self.app.test_request_context('/token/setrandompin',
                                           method='POST',
                                           data={"serial": t.token.serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            self.assertIn("You need to specify a policy 'otp_pin_set_random' in scope admin.",
                          result.get("error").get("message"))

        # Admin policy: admin is allowed to set random pin
        set_policy("allowed_to_set_pin", scope=SCOPE.ADMIN, action="{0!s}".format(ACTION.SETRANDOMPIN))
        # at least we need a otppinrandom policy (but not with length 0
        set_policy("pinpolrandom", scope=SCOPE.ADMIN, action="{0!s}=0".format(ACTION.OTPPINSETRANDOM))

        with self.app.test_request_context('/token/setrandompin',
                                           method='POST',
                                           data={"serial": t.token.serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            self.assertIn("We have an empty PIN. Please check your policy 'otp_pin_set_random'.",
                          result.get("error").get("message"))

        # at least we need a otppinrandom policy
        set_policy("pinpolrandom", scope=SCOPE.ADMIN, action="{0!s}=10".format(ACTION.OTPPINSETRANDOM))

        with self.app.test_request_context('/token/setrandompin',
                                           method='POST',
                                           data={"serial": t.token.serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            self.assertEqual(10, len(detail.get("pin")))

        # What happens, if we have two contradicting policies:
        set_policy("pinpolrandom2", scope=SCOPE.ADMIN, action="{0!s}=9".format(ACTION.OTPPINSETRANDOM))

        with self.app.test_request_context('/token/setrandompin',
                                           method='POST',
                                           data={"serial": t.token.serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 403, res)
            result = res.json.get("result")
            # contradicting values
            self.assertEqual(303, result.get("error").get("code"))

        # Now we adapt the priority of the policies:
        set_policy("pinpolrandom2", scope=SCOPE.ADMIN, action="{0!s}=9".format(ACTION.OTPPINSETRANDOM), priority=1)
        set_policy("pinpolrandom", scope=SCOPE.ADMIN, action="{0!s}=10".format(ACTION.OTPPINSETRANDOM), priority=2)

        with self.app.test_request_context('/token/setrandompin',
                                           method='POST',
                                           data={"serial": t.token.serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            detail = res.json.get("detail")
            self.assertEqual(9, len(detail.get("pin")))

        delete_policy("allowed_to_set_pin")
        delete_policy("pinpolrandom")
        delete_policy("pinpolrandom2")


class API00TokenPerformance(MyApiTestCase):

    token_count = 21

    def test_00_create_some_tokens(self):
        for i in range(0,self.token_count):
            init_token({"genkey": 1, "serial": "perf{0!s:0>3}".format(i)})
        toks = get_tokens(serial_wildcard="perf*")
        self.assertEqual(len(toks), self.token_count)

        for i in range(0,10):
            init_token({"genkey": 1, "serial": "TOK{0!s:0>3}".format(i)})
        toks = get_tokens(serial_wildcard="TOK*")
        self.assertEqual(len(toks), 10)

        self.setUp_user_realms()

    def test_01_number_of_tokens(self):
        # The GET /token returns a wildcard 100 tokens
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           data={"serial": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertEqual(result.get("value").get("count"), self.token_count)

        init_token({"genkey": 1, "serial": "realmtoken"}, tokenrealms=[self.realm1])
        toks = get_tokens(realm="*realm1*")
        self.assertEqual(len(toks), 1)

        # Request tokens in tokenrealm
        with self.app.test_request_context('/token/',
                                           method='GET',
                                           data={"tokenrealm": "**"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            # Even if we fetch tokenrealm=** we also get all the tokens without a tokenrealm
            self.assertEqual(result.get("value").get("count"), self.token_count + 10 + 1)

        with self.app.test_request_context('/token/',
                                           method='GET',
                                           data={"tokenrealm": "*alm1*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertEqual(result.get("value").get("count"), 1)

        remove_token(serial="realmtoken")

    def test_02_several_requests(self):
        # Run GET challenges
        with self.app.test_request_context('/token/challenges/*',
                                           method='GET',
                                           data={"serial": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 200, res)
            result = res.json.get("result")
            self.assertEqual(result.get("value").get("count"), 0)

        # Run POST assign with a wildcard. This shall not assign.
        with self.app.test_request_context('/token/assign',
                                           method='POST',
                                           data={"user": "cornelius",
                                                 "realm": self.realm1,
                                                 "serial": "perf*",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*"
            self.assertFalse(result["status"])

        # run POST unassign with a wildcard. This shall not unassign
        from privacyidea.lib.token import assign_token, unassign_token
        assign_token("perf001", User("cornelius", self.realm1))
        with self.app.test_request_context('/token/unassign',
                                           method='POST',
                                           data={"serial": "perf*",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # Now we unassign the token anyways
        unassign_token("perf001")

        # run POST revoke with a wildcard
        with self.app.test_request_context('/token/revoke',
                                           method='POST',
                                           data={"serial": "perf*",
                                                 "pin": "test"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # run POST enable and disable with a wildcard
        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={"serial": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        with self.app.test_request_context('/token/enable',
                                           method='POST',
                                           data={"serial": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # run DELETE /token with a wildcard
        with self.app.test_request_context('/token/perf*',
                                           method='DELETE',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # run reset failcounter
        with self.app.test_request_context('/token/reset/perf*',
                                           method='POST',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # run reset failcounter
        with self.app.test_request_context('/token/resync/perf*',
                                           method='POST', data={"otp1": "123454",
                                                                "otp2": "123454"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # Try to set pin
        with self.app.test_request_context('/token/setpin/perf*',
                                           method='POST', data={"otppin": "123454"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # Try to set description
        with self.app.test_request_context('/token/set/perf*',
                                           method='POST', data={"description": "general token"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # Try to set realm
        with self.app.test_request_context('/token/realm/perf*',
                                           method='POST', data={"realms": self.realm1},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # Try to copy the pin
        with self.app.test_request_context('/token/copypin',
                                           method='POST',
                                           data={"from": "perf*",
                                                 "to": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertEqual(result.get("error").get("code"), 1016)
            self.assertEqual(result.get("error").get("message"), "ERR1016: No unique token to copy from found")

        with self.app.test_request_context('/token/copypin',
                                           method='POST',
                                           data={"from": "perf001",
                                                 "to": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertEqual(result.get("error").get("code"), 1017)
            self.assertEqual(result.get("error").get("message"), "ERR1017: No unique token to copy to found")

        # Try to copy the user
        with self.app.test_request_context('/token/copyuser',
                                           method='POST',
                                           data={"from": "perf*",
                                                 "to": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertEqual(result.get("error").get("code"), 1016)
            self.assertEqual(result.get("error").get("message"), "ERR1016: No unique token to copy from found")

        # Try to copy the user
        with self.app.test_request_context('/token/copyuser',
                                           method='POST',
                                           data={"from": "perf001",
                                                 "to": "perf*"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertTrue(res.status_code == 400, res)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertEqual(result.get("error").get("code"), 1017)
            self.assertEqual(result.get("error").get("message"), "ERR1017: No unique token to copy to found")



        # Try to mark wildcard token as lost
        # Just to be clear, all tokens are assigned to the user cornelius
        for i in range(0,self.token_count):
            assign_token("perf{0!s:0>3}".format(i), User("cornelius", self.realm1))

        with self.app.test_request_context('/token/lost/perf*',
                                           method='POST',
                                           data={},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

        # unassign tokens again
        for i in range(0,self.token_count):
            unassign_token("perf{0!s:0>3}".format(i))

        # Try to set tokeninfo
        with self.app.test_request_context('/token/info/perf*/newkey',
                                           method='POST',
                                           data={"value": "newvalue"},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])

            toks = get_tokens(tokeninfo={"newkey": "newvalue"})
            # No token reveived this value!
            self.assertEqual(len(toks), 0)

        # Try to delete tokeninfo
        with self.app.test_request_context('/token/info/perf*/newkey',
                                           method='DELETE',
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 404)
            result = res.json.get("result")
            # Of course there is no exact token "perf*", it does not match perf001
            self.assertFalse(result["status"])


class APIDetermine_User_from_Serial_for_Policies(MyApiTestCase):
    """
    This Testclass verifies if a request, that only contains a serial will also
    honour policies, that are configured for users, if the serial is assigned to such a user.
    """

    def test_00_setup(self):
        self.setUp_user_realms()
        self.setUp_user_realm2()

    def test_01_disabling_token(self):
        serial = "SPASS001"
        polname = "disabletokens"

        t = init_token({"type": "spass", "serial": serial}, user=User("cornelius", self.realm1))

        # We are using the "testadmin"
        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={"serial": serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200)
            result = res.json.get("result")
            # One token disabled
            self.assertEqual(1, result.get("value"))

        enable_token(serial)
        # create a policy for realm1, the admin is allowed to disable the token
        set_policy(polname, scope=SCOPE.ADMIN, action=ACTION.DISABLE, realm=self.realm1, adminuser="testadmin")

        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={"serial": serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 200)
            result = res.json.get("result")
            # One token disabled
            self.assertEqual(1, result.get("value"))

        enable_token(serial)
        # change the policy for realm2, the admin is NOT allowed to disable the token
        set_policy(polname, scope=SCOPE.ADMIN, action=ACTION.DISABLE, realm=self.realm2, adminuser="testadmin")

        with self.app.test_request_context('/token/disable',
                                           method='POST',
                                           data={"serial": serial},
                                           headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(res.status_code, 403)
            result = res.json.get("result")
            # One token disabled
            self.assertFalse(result.get("status"))
            self.assertEqual(303, result.get("error").get("code"))
            self.assertEqual(u"Admin actions are defined, but the action disable is not allowed!",
                             result.get("error").get("message"))

        remove_token(serial)
        delete_policy(polname)
