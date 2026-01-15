from .utils import KerberosTestCase, random_string

import kadmin


class TestPolicy(KerberosTestCase):
    def test_list_policies(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        self.assertEqual(
            kadm.list_policies("*"),
            [],
        )

    def test_policy_exists(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        polname = random_string(16)
        kadm.add_policy(polname)
        self.assertTrue(kadm.policy_exists(polname))
        kadm.delete_policy(polname)

    def test_create_policy(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        polname = random_string(16)
        policy = kadm.add_policy(polname)
        self.assertEqual(policy.name, polname)
        self.assertIsNone(policy.password_max_life)
        self.assertEqual(policy.attributes, 0)
        kadm.delete_policy(polname)

    def test_delete_policy(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        polname = random_string(16)
        policy = kadm.add_policy(polname)
        self.assertTrue(kadm.policy_exists(polname))
        policy.delete(kadm)
        self.assertFalse(kadm.policy_exists(polname))

    def test_modify(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        polname = random_string(16)
        policy = kadm.add_policy(polname)
        policy = policy.modify(kadm, password_min_length=42)
        self.assertNotEqual(policy, None)
        assert policy is not None
        self.assertEqual(policy.password_min_length, 42)
        policy = kadm.get_policy(polname)
        self.assertNotEqual(policy, None)
        assert policy is not None
        self.assertEqual(policy.password_min_length, 42)
        kadm.delete_policy(polname)
