use anyhow::Result;
use kadmin::KAdmin;
#[cfg(feature = "client")]
use kadmin::KAdminImpl;
#[cfg(feature = "local")]
use kadmin::{KAdminDbArgs, KAdminParams};
use serial_test::serial;
mod k5test;
use k5test::K5Test;

#[cfg(feature = "client")]
#[test]
#[serial]
fn with_password() -> Result<()> {
    let realm = K5Test::new()?;
    let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
    kadmin.list_principals("*")?;
    Ok(())
}

#[cfg(feature = "client")]
#[test]
#[serial]
fn with_keytab() -> Result<()> {
    let realm = K5Test::new()?;
    let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
    kadmin.list_principals("*")?;
    Ok(())
}

#[cfg(feature = "client")]
#[test]
#[serial]
fn with_ccache() -> Result<()> {
    let realm = K5Test::new()?;
    realm.prep_kadmin()?;
    let kadmin_ccache = realm.kadmin_ccache()?;
    let kadmin = KAdmin::builder().with_ccache(Some(&realm.admin_princ()?), Some(&kadmin_ccache))?;
    kadmin.list_principals("*")?;
    Ok(())
}

#[cfg(feature = "local")]
#[test]
#[serial]
fn with_local() -> Result<()> {
    let realm = K5Test::new()?;
    let db_args = KAdminDbArgs::builder()
        .arg("dbname", Some(&format!("{}/db", realm.tmpdir()?)))
        .build()?;
    let params = KAdminParams::builder()
        .dbname(&format!("{}/db", realm.tmpdir()?))
        .acl_file(&format!("{}/acl", realm.tmpdir()?))
        .dict_file(&format!("{}/dict", realm.tmpdir()?))
        .stash_file(&format!("{}/stash", realm.tmpdir()?))
        .build()?;
    let _kadmin = KAdmin::builder().db_args(db_args).params(params).with_local()?;
    Ok(())
}

mod sync {
    use anyhow::Result;
    #[cfg(feature = "client")]
    use kadmin::KAdminImpl;
    use kadmin::sync::KAdmin;
    #[cfg(feature = "local")]
    use kadmin::{KAdminDbArgs, KAdminParams};
    use serial_test::serial;

    use crate::K5Test;

    #[cfg(feature = "client")]
    #[test]
    #[serial]
    fn with_password() -> Result<()> {
        let realm = K5Test::new()?;
        let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
        kadmin.list_principals("*")?;
        Ok(())
    }

    #[cfg(feature = "client")]
    #[test]
    #[serial]
    fn with_keytab() -> Result<()> {
        let realm = K5Test::new()?;
        let kadmin = KAdmin::builder().with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
        kadmin.list_principals("*")?;
        Ok(())
    }

    #[cfg(feature = "client")]
    #[test]
    #[serial]
    fn with_ccache() -> Result<()> {
        let realm = K5Test::new()?;
        realm.prep_kadmin()?;
        let kadmin_ccache = realm.kadmin_ccache()?;
        let kadmin = KAdmin::builder().with_ccache(Some(&realm.admin_princ()?), Some(&kadmin_ccache))?;
        kadmin.list_principals("*")?;
        Ok(())
    }

    #[cfg(feature = "local")]
    #[test]
    #[serial]
    fn with_local() -> Result<()> {
        let realm = K5Test::new()?;
        let db_args_builder = KAdminDbArgs::builder().arg("dbname", Some(&format!("{}/db", realm.tmpdir()?)));
        let params_builder = KAdminParams::builder()
            .dbname(&format!("{}/db", realm.tmpdir()?))
            .acl_file(&format!("{}/acl", realm.tmpdir()?))
            .dict_file(&format!("{}/dict", realm.tmpdir()?))
            .stash_file(&format!("{}/stash", realm.tmpdir()?));
        let _kadmin = KAdmin::builder()
            .db_args_builder(db_args_builder)
            .params_builder(params_builder)
            .with_local()?;
        Ok(())
    }
}
