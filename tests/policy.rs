//! Test policies
mod k5test;
mod util;

macro_rules! gen_tests {
    ($libname:ident, $variant:ident) => {
        #[cfg($libname)]
        mod $libname {
            use anyhow::Result;
            use kadmin::{KAdm5Variant, KAdminImpl, Policy};
            use serial_test::serial;

            use super::{
                super::{k5test::K5Test, util::random_string},
                *,
            };

            #[test]
            #[serial]
            fn list_policies() -> Result<()> {
                let realm = K5Test::new()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let policies = kadmin.list_policies(Some("*"))?;
                assert!(policies.is_empty());
                Ok(())
            }

            #[test]
            #[serial]
            fn policy_exists() -> Result<()> {
                let realm = K5Test::new()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let polname = random_string(16);
                Policy::builder(&polname).create(&kadmin)?;
                assert!(kadmin.policy_exists(&polname)?);
                Ok(())
            }

            #[test]
            #[serial]
            fn create_policy() -> Result<()> {
                let realm = K5Test::new()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let polname = random_string(16);
                let policy = Policy::builder(&polname).create(&kadmin)?;
                assert_eq!(policy.name(), &polname);
                assert_eq!(policy.password_max_life(), None);
                assert_eq!(policy.attributes(), 0);
                Ok(())
            }

            #[test]
            #[serial]
            fn delete_policy() -> Result<()> {
                let realm = K5Test::new()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let polname = random_string(16);
                let policy = Policy::builder(&polname).create(&kadmin)?;
                assert!(kadmin.policy_exists(&polname)?);
                policy.delete(&kadmin)?;
                assert!(!kadmin.policy_exists(&polname)?);
                Ok(())
            }

            #[test]
            #[serial]
            fn modify_policy() -> Result<()> {
                let realm = K5Test::new()?;
                let kadmin = KAdmin::builder(KAdm5Variant::$variant)
                    .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
                let polname = random_string(16);
                let policy = Policy::builder(&polname).create(&kadmin)?;
                let policy = policy.modifier().password_min_length(42).modify(&kadmin)?;
                assert_eq!(policy.password_min_length(), 42);
                let policy = kadmin.get_policy(&polname)?.unwrap();
                assert_eq!(policy.password_min_length(), 42);
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

mod sync {
    use kadmin::sync::KAdmin;

    gen_tests!(mit_client, MitClient);
    gen_tests!(mit_server, MitServer);
}
