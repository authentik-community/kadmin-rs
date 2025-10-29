# Rust and Python bindings for the Kerberos administration interface (kadm5)

This repository contains both a work-in-progress safe, idiomatic Rust bindings for libkadm5, the library to administrate a Kerberos realm that supports the Kerberos administration interface (mainly Heimdal and MIT Kerberos 5).

It also contains a Python API to those bindings.

## kadmin

![Crates.io Version](https://img.shields.io/crates/v/kadmin)
![docs.rs](https://img.shields.io/docsrs/kadmin)
![Maintenance](https://img.shields.io/maintenance/maintained/2025)

This is a safe, idiomatic Rust interface to libkadm5.

This library does not link against libkadm5, but instead loads it at runtime to be able to
support multiple variants.

It provides four features, all enabled by default, for the supported variants of libkadm5:

- `mit_client`
- `mit_server`
- `heimdal_client`
- `heimdal_server`

For remote operations:

```rust
use kadmin::{KAdm5Variant, KAdmin, KAdminImpl};

let princ = "user/admin@EXAMPLE.ORG";
let password = "vErYsEcUrE";

let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    .with_password(&princ, &password)
    .unwrap();

dbg!("{}", kadmin.list_principals(None).unwrap());
```

For local operations:

```rust
use kadmin::{KAdm5Variant, KAdmin, KAdminImpl};

let kadmin = KAdmin::builder(KAdm5Variant::MitServer)
    .with_local()
    .unwrap();

dbg!("{}", kadmin.list_principals(None).unwrap());
```

#### About compilation

During compilation, all the enabled variants will be discovered and bindings will be generated
from the discovered variants. If a variant cannot be discovered, it will not be available for
use. The following environment variables are available to override that discovery process:

To override the directories in which the `kadm5/admin.h` header will be searched for:

- `KADMIN_MIT_CLIENT_INCLUDES`
- `KADMIN_MIT_SERVER_INCLUDES`
- `KADMIN_HEIMDAL_CLIENT_INCLUDES`
- `KADMIN_HEIMDAL_SERVER_INCLUDES`

To override the path to the `krb5-config` binary:

- `KADM5_MIT_CLIENT_KRB5_CONFIG`
- `KADM5_MIT_SERVER_KRB5_CONFIG`
- `KADM5_HEIMDAL_CLIENT_KRB5_CONFIG`
- `KADM5_HEIMDAL_SERVER_KRB5_CONFIG`

Library paths will also be looked for, and forwarded so that at runtime, the library can be
loaded. If it cannot find any, it will try to load a generic library from the system library
paths. You can override the path the library is loaded from with [`sys::Library::from_path`].

#### About thread safety

As far as I can tell, libkadm5 APIs are **not** thread safe. As such, the types provided by this crate are neither `Send` nor `Sync`. You _must not_ use those with threads. You can either create a `KAdmin` instance per thread, or use the `kadmin::sync::KAdmin` interface that spawns a thread and sends the various commands to it. The API is not exactly the same as the non-thread-safe one, but should be close enough that switching between one or the other is easy enough. Read more about this in the documentation of the crate.

## python-kadmin-rs

![PyPI - Version](https://img.shields.io/pypi/v/python-kadmin-rs)
![Read the Docs](https://img.shields.io/readthedocs/kadmin-rs)
![Maintenance](https://img.shields.io/maintenance/maintained/2025)

These are Python bindings to the above Rust library, using the `kadmin::sync` interface to ensure thread safety.

For remote operations:

```python
import kadmin

princ = "user/admin@EXAMPLE.ORG"
password = "vErYsEcUrE"
kadm = kadmin.KAdmin.with_password(kadmin.KAdm5Variant.MitClient, princ, password)
print(kadm.list_principals("*"))
```

For local operations:

```python
import kadmin

kadm = kadmin.KAdmin.with_local(kadmin.KAdm5Variant.MitClient)
print(kadm.list_principals("*"))
```

## License

Licensed under the [MIT License](./LICENSE).

## Contributing

Just open a PR.

### Releasing

1. Go to [Actions > Create release PR](https://github.com/authentik-community/kadmin-rs/actions/workflows/release-pr.yml)
2. Click "Run workflow" and select what you need to release and input the new version.
3. Wait for the PR to be opened and the CI to pass
4. Merge the PR.
5. Go to [Releases](https://github.com/authentik-community/kadmin-rs/releases)
6. Edit the created release.
7. Click "Generate release notes"
8. Publish
