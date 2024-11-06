from .utils import KerberosTestCase

import kadmin


class TestInit(KerberosTestCase):
    def test_list_principals(self):
        kadm = kadmin.KAdmin.with_password(
            self.realm.admin_princ, self.realm.password("admin")
        )
        self.assertEqual(
            [
                princ
                for princ in kadm.list_principals("*")
                if not princ.startswith("host/")
            ],
            [
                "HTTP/testserver@KRBTEST.COM",
                "K/M@KRBTEST.COM",
                "kadmin/admin@KRBTEST.COM",
                "kadmin/changepw@KRBTEST.COM",
                "krbtgt/KRBTEST.COM@KRBTEST.COM",
                "user/admin@KRBTEST.COM",
                "user@KRBTEST.COM",
            ],
        )

    def test_principal_exists(self):
        kadm = kadmin.KAdmin.with_password(
            self.realm.admin_princ, self.realm.password("admin")
        )
        self.assertTrue(kadm.principal_exists(self.realm.user_princ))
        self.assertFalse(kadm.principal_exists(f"nonexistent@{self.realm.realm}"))
