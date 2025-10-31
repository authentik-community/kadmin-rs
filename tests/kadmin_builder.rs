//! Test KAdmin builders
use anyhow::Result;
use kadmin::{DbArgs, KAdmin, KAdminImpl, Params};
use serial_test::serial;
mod k5test;
use k5test::K5Test;
use kadmin::KAdm5Variant;

#[test]
#[serial]
fn with_password() -> Result<()> {
    let realm = K5Test::new(KAdm5Variant::MitClient)?;
    let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
        .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
    kadmin.list_principals(None)?;
    Ok(())
}

#[test]
#[serial]
fn with_password_heimdal() -> Result<()> {
    let realm = K5Test::new(KAdm5Variant::HeimdalClient)?;
    let kadmin = KAdmin::builder(KAdm5Variant::HeimdalClient)
        .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
    kadmin.list_principals(None)?;
    Ok(())
}

#[test]
#[serial]
fn with_keytab() -> Result<()> {
    let realm = K5Test::new(KAdm5Variant::MitClient)?;
    let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
        .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
    kadmin.list_principals(None)?;
    Ok(())
}

#[test]
#[serial]
fn with_ccache() -> Result<()> {
    let realm = K5Test::new(KAdm5Variant::MitClient)?;
    realm.prep_kadmin()?;
    let kadmin_ccache = realm.kadmin_ccache()?;
    let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
        .with_ccache(Some(&realm.admin_princ()?), Some(&kadmin_ccache))?;
    kadmin.list_principals(None)?;
    Ok(())
}

#[test]
#[serial]
fn with_local() -> Result<()> {
    let realm = K5Test::new(KAdm5Variant::MitServer)?;
    let db_args = DbArgs::builder()
        .arg("dbname", Some(&format!("{}/db", realm.tmpdir()?)))
        .build()?;
    let params = Params::new()
        .dbname(&format!("{}/db", realm.tmpdir()?))
        .acl_file(&format!("{}/acl", realm.tmpdir()?))
        .dict_file(&format!("{}/dict", realm.tmpdir()?))
        .stash_file(&format!("{}/stash", realm.tmpdir()?));
    let kadmin = KAdmin::builder(KAdm5Variant::MitServer)
        .db_args(db_args)
        .params(params)
        .with_local()?;
    kadmin.list_principals(None)?;
    Ok(())
}

mod sync {
    use anyhow::Result;
    use kadmin::{DbArgs, KAdm5Variant, KAdminImpl, Params, sync::KAdmin};
    use serial_test::serial;

    use crate::K5Test;

    #[test]
    #[serial]
    fn with_password() -> Result<()> {
        let realm = K5Test::new(KAdm5Variant::MitClient)?;
        let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
            .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
        kadmin.list_principals(None)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn with_keytab() -> Result<()> {
        let realm = K5Test::new(KAdm5Variant::MitClient)?;
        let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
            .with_password(&realm.admin_princ()?, &realm.password("admin")?)?;
        kadmin.list_principals(None)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn with_ccache() -> Result<()> {
        let realm = K5Test::new(KAdm5Variant::MitClient)?;
        realm.prep_kadmin()?;
        let kadmin_ccache = realm.kadmin_ccache()?;
        let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
            .with_ccache(Some(&realm.admin_princ()?), Some(&kadmin_ccache))?;
        kadmin.list_principals(None)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn with_local() -> Result<()> {
        let realm = K5Test::new(KAdm5Variant::MitServer)?;
        let db_args = DbArgs::builder()
            .arg("dbname", Some(&format!("{}/db", realm.tmpdir()?)))
            .build()?;
        let params = Params::new()
            .dbname(&format!("{}/db", realm.tmpdir()?))
            .acl_file(&format!("{}/acl", realm.tmpdir()?))
            .dict_file(&format!("{}/dict", realm.tmpdir()?))
            .stash_file(&format!("{}/stash", realm.tmpdir()?));
        let _kadmin = KAdmin::builder(KAdm5Variant::MitServer)
            .db_args(db_args)
            .params(params)
            .with_local()?;
        Ok(())
    }
}
