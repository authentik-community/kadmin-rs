from datetime import timedelta
from .utils import KerberosTestCase, random_string

import kadmin


class TestPrincipal(KerberosTestCase):
    def test_list_principals(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
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
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        self.assertTrue(kadm.principal_exists(self.realm.user_princ))
        self.assertFalse(kadm.principal_exists(f"nonexistent@{self.realm.realm}"))

    def test_get_principal(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princ = kadm.get_principal(self.realm.user_princ)
        self.assertNotEqual(princ, None)
        assert princ is not None
        self.assertEqual(princ.name, self.realm.user_princ)

    def test_create_principal(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princname = random_string(16)
        princ = kadm.add_principal(princname)
        self.assertEqual(princ.name, f"{princname}@KRBTEST.COM")
        self.assertEqual(princ.max_life, timedelta(seconds=86400))
        self.assertEqual(princ.attributes, 0)

        princ.delete(kadm)

    def test_delete_principal(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princname = random_string(16)
        princ = kadm.add_principal(princname)
        self.assertTrue(kadm.principal_exists(princname))
        princ.delete(kadm)
        self.assertFalse(kadm.principal_exists(princname))

    def test_modify_principal(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princname = random_string(16)
        princ = kadm.add_principal(princname)
        self.assertIsNotNone(princ)
        assert princ is not None
        princ = princ.modify(
            kadm, attributes=kadmin.sys.mit_client.KRB5_KDB_REQUIRES_PRE_AUTH
        )
        self.assertEqual(
            princ.attributes, kadmin.sys.mit_client.KRB5_KDB_REQUIRES_PRE_AUTH
        )
        princ = kadm.get_principal(princname)
        self.assertIsNotNone(princ)
        assert princ is not None
        self.assertEqual(
            princ.attributes, kadmin.sys.mit_client.KRB5_KDB_REQUIRES_PRE_AUTH
        )

        princ.delete(kadm)

    def test_change_password(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princ = kadm.get_principal(self.realm.user_princ)
        self.assertIsNotNone(princ)
        assert princ is not None
        princ.change_password(kadm, "new_password")
        self.realm.kinit(self.realm.user_princ, "new_password")
        # Restore password
        princ.change_password(kadm, self.realm.password("user"))

    def test_randkey(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        princ = kadm.get_principal(self.realm.user_princ)
        self.assertIsNotNone(princ)
        assert princ is not None
        princ.randkey(kadm)
        with self.assertRaises(Exception):
            self.realm.kinit(self.realm.user_princ, "new_password")
        # Restore password
        princ.change_password(kadm, self.realm.password("user"))
