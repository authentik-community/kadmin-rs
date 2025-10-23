//! Test policies
use anyhow::Result;
use kadmin::{KAdm5Variant, KAdmin, KAdminImpl, Policy};
use serial_test::serial;
mod k5test;
use k5test::K5Test;
mod util;
use util::random_string;

macro_rules! gen_tests {
    () => {
        #[test]
        #[serial]
        fn list_policies() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let policies = kadmin.list_policies(Some("*"))?;
            assert!(policies.is_empty());
            Ok(())
        }

        #[test]
        #[serial]
        fn policy_exists() -> Result<()> {
            let realm = K5Test::new()?;
            let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
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
            let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
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
            let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
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
            let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
                .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
            let polname = random_string(16);
            let policy = Policy::builder(&polname).create(&kadmin)?;
            let policy = policy.modifier().password_min_length(42).modify(&kadmin)?;
            assert_eq!(policy.password_min_length(), 42);
            let policy = kadmin.get_policy(&polname)?.unwrap();
            assert_eq!(policy.password_min_length(), 42);
            Ok(())
        }
    };
}

gen_tests!();

// mod sync {
//     use anyhow::Result;
//     use kadmin::{KAdminImpl, Policy, sync::KAdmin};
//     use serial_test::serial;
//
//     use crate::{K5Test, random_string};
//
//     gen_tests!();
// }
