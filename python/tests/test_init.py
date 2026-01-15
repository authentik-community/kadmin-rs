from .utils import KerberosTestCase

import kadmin


class TestInit(KerberosTestCase):
    def test_with_password(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        kadm.list_principals("*")

    def test_with_keytab(self):
        kadm = kadmin.KAdmin.with_password(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.password("admin"),
        )
        kadm.list_principals("*")

    def test_with_ccache(self):
        self.realm.prep_kadmin()
        kadm = kadmin.KAdmin.with_ccache(
            kadmin.KAdm5Variant.MitClient,
            self.realm.admin_princ,
            self.realm.kadmin_ccache,
        )
        kadm.list_principals("*")

    def test_with_local(self):
        db_args = kadmin.DbArgs(dbname=f"{self.realm.tmpdir}/db")
        params = kadmin.Params(
            dbname=f"{self.realm.tmpdir}/db",
            acl_file=f"{self.realm.tmpdir}/acl",
            dict_file=f"{self.realm.tmpdir}/dict",
            stash_file=f"{self.realm.tmpdir}/stash",
        )
        kadm = kadmin.KAdmin.with_local(
            kadmin.KAdm5Variant.MitServer,
            db_args=db_args,
            params=params,
        )
        kadm.list_principals("*")
