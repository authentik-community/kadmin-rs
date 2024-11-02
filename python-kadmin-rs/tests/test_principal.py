from .utils import KerberosTestCase

import kadmin


class TestInit(KerberosTestCase):
    def test_list_principals(self):
        kadm = kadmin.KAdmin.with_password(
            self.realm.admin_princ, self.realm.password("admin")
        )
        self.assertEqual(
            kadm.list_principals("*"),
            [
                "HTTP/testserver@KRBTEST.COM",
                "K/M@KRBTEST.COM",
                "host/localhost@KRBTEST.COM",
                "kadmin/admin@KRBTEST.COM",
                "kadmin/changepw@KRBTEST.COM",
                "krbtgt/KRBTEST.COM@KRBTEST.COM",
                "user/admin@KRBTEST.COM",
                "user@KRBTEST.COM",
            ],
        )
