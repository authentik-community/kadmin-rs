from .utils import KerberosTestCase

import kadmin
import kadmin_local


class TestInit(KerberosTestCase):
    def test_with_password(self):
        kadm = kadmin.KAdmin.with_password(
            self.realm.admin_princ, self.realm.password("admin")
        )
        kadm.list_principals("*")

    def test_with_keytab(self):
        kadm = kadmin.KAdmin.with_password(
            self.realm.admin_princ, self.realm.password("admin")
        )
        kadm.list_principals("*")

    def test_with_ccache(self):
        self.realm.prep_kadmin()
        kadm = kadmin.KAdmin.with_ccache(
            self.realm.admin_princ, self.realm.kadmin_ccache
        )
        kadm.list_principals("*")

    def test_with_local(self):
        db_args = kadmin_local.DbArgs(dbname=f"{self.realm.tmpdir}/db")
        params = kadmin_local.Params(
            dbname=f"{self.realm.tmpdir}/db",
            acl_file=f"{self.realm.tmpdir}/acl",
            dict_file=f"{self.realm.tmpdir}/dict",
            stash_file=f"{self.realm.tmpdir}/stash",
        )
        kadm = kadmin_local.KAdmin.with_local(db_args=db_args, params=params)
        kadm.list_principals("*")
