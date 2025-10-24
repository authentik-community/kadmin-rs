//! Test principals
#[cfg(feature = "client")]
use anyhow::Result;
#[cfg(feature = "client")]
use kadmin::{KAdmin, KAdminImpl, Principal, PrincipalAttributes};
#[cfg(feature = "client")]
use serial_test::serial;
mod k5test;
#[cfg(feature = "client")]
use k5test::K5Test;
mod util;
#[cfg(feature = "client")]
use util::random_string;

macro_rules! gen_tests {
    () => {
        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn list_principals() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
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

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn principal_exists() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            assert!(kadmin.principal_exists(&realm.user_princ()?)?);
            assert!(!kadmin.principal_exists(&format!("nonexistent@{}", &realm.realm_name()?))?);
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn get_principal() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?;
            assert!(princ.is_some());
            let princ = princ.unwrap();
            assert_eq!(princ.name(), &realm.user_princ()?);
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn create_principal() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princname = random_string(16);
            let princ = Principal::builder(&princname).create(&kadmin)?;
            assert_eq!(princ.name(), format!("{princname}@KRBTEST.COM"));
            assert_eq!(
                princ.max_life(),
                Some(std::time::Duration::from_secs(86400))
            );
            assert_eq!(princ.attributes(), PrincipalAttributes::from_bits_retain(0));
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn delete_principal() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princname = random_string(16);
            let princ = Principal::builder(&princname).create(&kadmin)?;
            assert!(kadmin.principal_exists(&princname)?);
            princ.delete(&kadmin)?;
            assert!(!kadmin.principal_exists(&princname)?);
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn modify_principal() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princname = random_string(16);
            let princ = Principal::builder(&princname).create(&kadmin)?;
            let princ = princ
                .modifier()
                .attributes(PrincipalAttributes::RequiresPreAuth)
                .modify(&kadmin)?;
            assert_eq!(princ.attributes(), PrincipalAttributes::RequiresPreAuth);
            let princ = kadmin.get_principal(&princname)?.unwrap();
            assert_eq!(princ.attributes(), PrincipalAttributes::RequiresPreAuth);
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn change_password() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
            princ.change_password(&kadmin, "new_password", None, None)?;
            realm.kinit(&realm.user_princ()?, "new_password")?;
            // Restore password
            princ.change_password(&kadmin, &realm.password("user")?, None, None)?;
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn randkey() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
            princ.randkey(&kadmin, None, None)?;
            assert!(realm.kinit(&realm.user_princ()?, "new_password").is_err());
            // Restore password
            princ.change_password(&kadmin, &realm.password("user")?, None, None)?;
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn unlock() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
            assert!(princ.unlock(&kadmin).is_ok());
            Ok(())
        }

        #[cfg(feature = "client")]
        #[test]
        #[serial]
        fn strings() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder()
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let princ = kadmin.get_principal(&realm.user_princ()?)?.unwrap();
            assert!(princ.get_strings(&kadmin)?.is_empty());
            princ.set_string(&kadmin, "key", Some("value"))?;
            let strings = princ.get_strings(&kadmin)?;
            assert!(strings.contains_key("key"));
            assert_eq!(strings.get("key"), Some(String::from("value")).as_ref());
            Ok(())
        }
    };
}

gen_tests!();

mod sync {
    #[cfg(feature = "client")]
    use anyhow::Result;
    #[cfg(feature = "client")]
    use kadmin::{KAdmin, KAdminImpl, Principal, PrincipalAttributes};
    #[cfg(feature = "client")]
    use serial_test::serial;

    #[cfg(feature = "client")]
    use crate::K5Test;
    #[cfg(feature = "client")]
    use crate::random_string;

    gen_tests!();
}
