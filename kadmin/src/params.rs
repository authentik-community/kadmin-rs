#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[cfg(mit)]
    #[test]
    fn build_empty_mit() {
        let params = Params::builder(KAdm5Variant::MitClient).build().unwrap();

        match params.inner {
            ParamsInner::Mit(p) => assert_eq!(p.params.mask, 0),
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_empty_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => assert_eq!(p.params.mask, 0),
            _ => unreachable!(),
        };
    }

    #[cfg(mit)]
    #[test]
    fn build_realm_mit() {
        let params = Params::builder(KAdm5Variant::MitClient)
            .realm("EXAMPLE.ORG")
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Mit(p) => {
                assert_eq!(p.params.mask, 1);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
            }
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_realm_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .realm("EXAMPLE.ORG")
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => {
                assert_eq!(p.params.mask, 1);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
            }
            _ => unreachable!(),
        };
    }

    #[cfg(mit)]
    #[test]
    fn build_all_mit() {
        let params = Params::builder(KAdm5Variant::MitClient)
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Mit(p) => {
                assert_eq!(p.params.mask, 0x94001);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(p.params.kadmind_port, 750);
                assert_eq!(p.params.kpasswd_port, 465);
            }
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_all_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => {
                assert_eq!(p.params.mask, 0xd);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(p.params.kadmind_port, 750);
            }
            _ => unreachable!(),
        };
    }
}
