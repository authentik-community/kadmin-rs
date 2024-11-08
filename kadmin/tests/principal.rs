#[cfg(feature = "client")]
use anyhow::Result;
#[cfg(feature = "client")]
use kadmin::{KAdmin, KAdminImpl};
#[cfg(feature = "client")]
use serial_test::serial;
mod k5test;
#[cfg(feature = "client")]
use k5test::K5Test;

macro_rules! gen_tests {
    () => {
        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn list_principals() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let principals = kadmin.list_principals("*")?;
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

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn principal_exists() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            assert!(kadmin.principal_exists(&realm.user_princ()?)?);
            assert!(!kadmin.principal_exists(&format!("nonexistent@{}", &realm.realm_name()?))?);
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn change_password() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
            princ.change_password(&kadmin, "new_password")?;
            realm.kinit(&realm.user_princ()?, "new_password")?;
            // Restore password
            princ.change_password(&kadmin, &realm.password("user")?)?;
            Ok(())
        }
    };
}

gen_tests!();

mod sync {
    #[cfg(feature = "client")]
    use anyhow::Result;
    #[cfg(feature = "client")]
    use kadmin::{KAdminImpl, sync::KAdmin};
    #[cfg(feature = "client")]
    use serial_test::serial;

    #[cfg(feature = "client")]
    use crate::K5Test;

    gen_tests!();
}
