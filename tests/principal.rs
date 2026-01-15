//! Test principals
mod k5test;
mod util;

macro_rules! gen_tests {
    ($libname:ident, $variant:ident) => {
        #[cfg($libname)]
        mod $libname {
            use anyhow::Result;
            use kadmin::{KAdm5Variant, KAdminImpl, Principal, sys};
            use serial_test::serial;

            use super::{
                super::{k5test::K5Test, util::random_string},
                *,
            };

            #[test]
            #[serial]
            fn list_principals() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let principals = kadmin.list_principals(Some("*"))?;
                assert_eq!(
                    principals
                        .into_iter()
                        .filter(|princ| !princ.starts_with("host/"))
                        .collect::<Vec<String>>(),
                    vec![
                        "HTTP/testserver@KRBTEST.COM",
                        "K/M@KRBTEST.COM",
                        "kadmin/admin@KRBTEST.COM",
                        "kadmin/changepw@KRBTEST.COM",
                        "krbtgt/KRBTEST.COM@KRBTEST.COM",
                        "user/admin@KRBTEST.COM",
                        "user@KRBTEST.COM",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>()
                );
                Ok(())
            }

            #[test]
            #[serial]
            fn principal_exists() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                assert!(kadmin.principal_exists(&realm.user_princ()?)?);
                assert!(
                    !kadmin.principal_exists(&format!("nonexistent@{}", &realm.realm_name()?))?
                );
                Ok(())
            }

            #[test]
            #[serial]
            fn get_principal() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princ = kadmin.get_principal(&realm.user_princ()?)?;
                assert!(princ.is_some());
                let princ = princ.unwrap();
                assert_eq!(princ.name(), &realm.user_princ()?);
                Ok(())
            }

            #[test]
            #[serial]
            fn create_principal() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princname = random_string(16);
                let princ = Principal::builder(&princname).create(&kadmin)?;
                assert_eq!(princ.name(), format!("{princname}@KRBTEST.COM"));
                assert_eq!(
                    princ.max_life(),
                    Some(std::time::Duration::from_secs(86400))
                );
                assert_eq!(princ.attributes(), 0);
                Ok(())
            }

            #[test]
            #[serial]
            fn delete_principal() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princname = random_string(16);
                let princ = Principal::builder(&princname).create(&kadmin)?;
                assert!(kadmin.principal_exists(&princname)?);
                princ.delete(&kadmin)?;
                assert!(!kadmin.principal_exists(&princname)?);
                Ok(())
            }

            #[test]
            #[serial]
            fn modify_principal() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princname = random_string(16);
                let princ = Principal::builder(&princname).create(&kadmin)?;
                let princ = princ
                    .modifier()
                    .attributes(sys::$libname::KRB5_KDB_REQUIRES_PRE_AUTH as i32)
                    .modify(&kadmin)?;
                assert_eq!(
                    princ.attributes(),
                    sys::$libname::KRB5_KDB_REQUIRES_PRE_AUTH as i32
                );
                let princ = kadmin.get_principal(&princname)?.unwrap();
                assert_eq!(
                    princ.attributes(),
                    sys::$libname::KRB5_KDB_REQUIRES_PRE_AUTH as i32
                );
                Ok(())
            }

            #[test]
            #[serial]
            fn change_password() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
                princ.change_password(&kadmin, "new_password", None, None)?;
                realm.kinit(&realm.user_princ()?, "new_password")?;
                // Restore password
                princ.change_password(&kadmin, &realm.password("user")?, None, None)?;
                Ok(())
            }

            #[test]
            #[serial]
            fn randkey() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
                princ.randkey(&kadmin, None, None)?;
                assert!(realm.kinit(&realm.user_princ()?, "new_password").is_err());
                // Restore password
                princ.change_password(&kadmin, &realm.password("user")?, None, None)?;
                Ok(())
            }

            #[test]
            #[serial]
            fn unlock() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
                assert!(princ.unlock(&kadmin).is_ok());
                Ok(())
            }

            #[test]
            #[serial]
            fn strings() -> Result<()> {
                let realm = K5Test::new(KAdm5Variant::$variant)?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
                assert!(princ.get_strings(&kadmin)?.is_empty());
                princ.set_string(&kadmin, "key", Some("value"))?;
                let strings = princ.get_strings(&kadmin)?;
                assert!(strings.contains_key("key"));
                assert_eq!(strings.get("key"), Some(String::from("value")).as_ref());
                Ok(())
            }
        }
    };
}

mod direct {
    use kadmin::KAdmin;

    gen_tests!(mit_client, MitClient);
    gen_tests!(mit_server, MitServer);
}

// mod sync {
//     use kadmin::sync::KAdmin;
//
//     gen_tests!(mit_client, MitClient);
//     gen_tests!(mit_server, MitServer);
// }
