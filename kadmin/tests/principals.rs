#[cfg(feature = "client")]
use anyhow::Result;
#[cfg(feature = "client")]
use kadmin::KAdmin;
#[cfg(feature = "client")]
use serial_test::serial;
mod k5test;
#[cfg(feature = "client")]
use k5test::K5Test;

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

mod sync {
    #[cfg(feature = "client")]
    use anyhow::Result;
    #[cfg(feature = "client")]
    use kadmin::sync::KAdmin;
    #[cfg(feature = "client")]
    use serial_test::serial;

    #[cfg(feature = "client")]
    use crate::K5Test;

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
}
