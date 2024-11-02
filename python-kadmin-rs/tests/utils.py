import os
from copy import deepcopy
from k5test import realm
from unittest import TestCase


class KerberosTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realm = realm.K5Realm(start_kadmind=True)

        cls.realm.http_princ = f"HTTP/testserver@{cls.realm.realm}"
        cls.realm.http_keytab = os.path.join(cls.realm.tmpdir, "http_keytab")
        cls.realm.addprinc(cls.realm.http_princ)
        cls.realm.extract_keytab(cls.realm.http_princ, cls.realm.http_keytab)

        cls._saved_env = deepcopy(os.environ)
        for k, v in cls.realm.env.items():
            os.environ[k] = v

    @classmethod
    def tearDownClass(cls):
        cls.realm.stop()
        del cls.realm

        for k in deepcopy(os.environ):
            if k in cls._saved_env:
                os.environ[k] = cls._saved_env[k]
            else:
                del os.environ[k]
        cls._saved_env = None
