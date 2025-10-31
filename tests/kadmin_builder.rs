//! Test KAdmin builders
mod k5test;

macro_rules! gen_tests_remote {
    ($libname: ident, $variant:ident) => {
        #[cfg($libname)]
        mod $libname {
            use anyhow::Result;
            use kadmin::{KAdm5Variant, KAdminImpl};
            use serial_test::serial;

            use super::{super::k5test::K5Test, *};

            #[test]
            #[serial]
            fn with_password() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                kadmin.list_principals(None)?;
                Ok(())
            }

            #[test]
            #[serial]
            fn with_keytab() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                kadmin.list_principals(None)?;
                Ok(())
            }

            #[test]
            #[serial]
            fn with_ccache() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                realm.prep_kadmin()?;
                let kadmin_ccache = realm.kadmin_ccache()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_ccache(Some(&realm.admin_princ()?), Some(&kadmin_ccache))?;
                kadmin.list_principals(None)?;
                Ok(())
            }
        }
    };
}

macro_rules! gen_tests_local {
    ($libname: ident, $variant:ident) => {
        #[cfg($libname)]
        mod $libname {
            use anyhow::Result;
            use kadmin::{DbArgs, KAdm5Variant, KAdminImpl, Params};
            use serial_test::serial;

            use super::{super::k5test::K5Test, *};

            #[test]
            #[serial]
            fn with_local() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let db_args = DbArgs::builder()
                    .arg("dbname", Some(&format!("{}/db", realm.tmpdir()?)))
                    .build()?;
                let mut params = Params::new()
                    .dbname(&format!("{}/db", realm.tmpdir()?))
                    .acl_file(&format!("{}/acl", realm.tmpdir()?))
                    .stash_file(&format!("{}/stash", realm.tmpdir()?));
                #[cfg(any(mit_client, mit_server))]
                {
                    params = params.dict_file(&format!("{}/dict", realm.tmpdir()?));
                }
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .db_args(db_args)
                    .params(params)
                    .with_local()?;
                kadmin.list_principals(None)?;
                Ok(())
            }
        }
    };
}

mod direct {
    use kadmin::KAdmin;

    gen_tests_remote!(mit_client, MitClient);
    gen_tests_remote!(heimdal_client, HeimdalClient);
    gen_tests_local!(mit_server, MitServer);
    gen_tests_local!(heimdal_server, HeimdalServer);
}

mod sync {
    use kadmin::sync::KAdmin;

    gen_tests_remote!(mit_client, MitClient);
    gen_tests_remote!(heimdal_client, HeimdalClient);
    gen_tests_local!(mit_server, MitServer);
    gen_tests_local!(heimdal_server, HeimdalServer);
}
