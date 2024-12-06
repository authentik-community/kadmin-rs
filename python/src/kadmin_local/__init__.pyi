from typing import List, Self, final
import datetime

__version__: str

@final
class KAdminApiVersion:
    Version2: Self
    Version3: Self
    Version4: Self

@final
class KAdmin:
    def add_principal(self, name, **kwargs) -> Principal: ...
    def rename_principal(self, old_name, new_name): ...
    def delete_principal(self, name): ...
    def get_principal(self, name: str) -> Principal | None: ...
    def principal_exists(self, name: str) -> bool: ...
    def principal_change_password(
        self,
        name: str,
        password: str,
        keepold: bool | None = None,
        keysalts: KeySalts | None = None,
    ): ...
    def principal_randkey(
        self, name: str, keepold: bool | None = None, keysalts: KeySalts | None = None
    ): ...
    def principal_get_strings(self, name: str) -> dict[str, str]: ...
    def principal_set_string(self, name: str, key: str, value: str | None): ...
    def list_principals(self, query: str | None = None) -> List[str]: ...
    def add_policy(self, name: str, **kwargs) -> Policy: ...
    def delete_policy(self, name: str) -> None: ...
    def get_policy(self, name: str) -> Policy | None: ...
    def policy_exists(self, name: str) -> bool: ...
    def list_policies(self, query: str | None = None) -> List[str]: ...
    @staticmethod
    def with_local(
        params: Params | None = None,
        db_args: DbArgs | None = None,
        api_version: KAdminApiVersion | None = None,
    ) -> KAdmin: ...

@final
class Policy:
    name: str
    password_min_life: datetime.timedelta | None
    password_max_life: datetime.timedelta | None
    password_min_length: int
    password_min_classes: int
    password_history_num: int
    policy_refcnt: int
    password_max_fail: int
    password_failcount_interval: datetime.timedelta | None
    password_lockout_duration: datetime.timedelta | None
    attributes: int
    max_life: datetime.timedelta | None
    max_renewable_life: datetime.timedelta | None
    allowed_keysalts: KeySalts | None
    tl_data: TlData

    def modify(self, kadmin: KAdmin, **kwargs) -> Policy: ...
    def delete(self, kadmin: KAdmin) -> None: ...

@final
class Principal:
    name: str
    expire_time: datetime.datetime | None
    last_password_change: datetime.datetime | None
    password_expiration: datetime.datetime | None
    max_life: datetime.timedelta | None
    modified_by: str
    modified_at: datetime.datetime | None
    attributes: int
    kvno: int
    mkvno: int
    policy: str | None
    aux_attributes: int
    max_renewable_life: datetime.timedelta | None
    last_success: datetime.datetime | None
    last_failed: datetime.datetime | None
    fail_auth_count: int
    tl_data: TlData

    def modify(self, kadmin: KAdmin, **kwargs) -> Policy: ...
    def delete(self, kadmin: KAdmin): ...
    def change_password(
        self,
        kadmin: KAdmin,
        password: str,
        keepold: bool | None = None,
        keysalts: KeySalts | None = None,
    ): ...
    def randkey(
        self,
        kadmin: KAdmin,
        keepold: bool | None = None,
        keysalts: KeySalts | None = None,
    ): ...
    def unlock(self, kadmin: KAdmin): ...
    def get_strings(self, kadmin: KAdmin) -> dict[str, str]: ...
    def set_string(self, kadmin: KAdmin, key: str, value: str | None): ...

@final
class PrincipalAttributes:
    DisallowPostdated: Self
    DisallowForwardable: Self
    DisallowTgtBased: Self
    DisallowRenewable: Self
    DisallowProxiable: Self
    DisallowDupSkey: Self
    DisallowAllTix: Self
    RequiresPreAuth: Self
    RequiresHwAuth: Self
    RequiresPwChange: Self
    DisallowSvr: Self
    PwChangeService: Self
    SupportDesMd5: Self
    NewPrinc: Self
    OkAsDelegate: Self
    OkToAuthAsDelegate: Self
    NoAuthDataRequired: Self
    LockdownKeys: Self

    def __init__(self, bits: int): ...
    def bits(self) -> int: ...

class NewPrincipalKey:
    @final
    class Password(NewPrincipalKey):
        __match_args__: tuple
        def __init__(self, password: str): ...

    @final
    class NoKey(NewPrincipalKey):
        __match_args__: tuple
        def __init__(self, *args, **kwargs): ...

    @final
    class RandKey(NewPrincipalKey):
        __match_args__: tuple
        def __init__(self, *args, **kwargs): ...

    @final
    class ServerRandKey(NewPrincipalKey):
        __match_args__: tuple
        def __init__(self, *args, **kwargs): ...

    @final
    class OldStyleRandKey(NewPrincipalKey):
        __match_args__: tuple
        def __init__(self, *args, **kwargs): ...

@final
class Params:
    def __init__(
        self,
        realm: str | None = None,
        kadmind_port: int | None = None,
        kpasswd_port: int | None = None,
        admin_server: str | None = None,
        dbname: str | None = None,
        acl_file: str | None = None,
        dict_file: str | None = None,
        stash_file: str | None = None,
    ): ...

@final
class DbArgs:
    def __init__(self, /, *args: str, **kwargs: str | None): ...

@final
class EncryptionType:
    Des3CbcRaw: Self
    Des3CbcSha1: Self
    ArcfourHmac: Self
    ArcfourHmacExp: Self
    Aes128CtsHmacSha196: Self
    Aes256CtsHmacSha196: Self
    Camellia128CtsCmac: Self
    Camellia256CtsCmac: Self
    Aes128CtsHmacSha256128: Self
    Aes256CtsHmacSha384192: Self

    def __init__(self, enctype: int | str): ...

@final
class SaltType:
    Normal: Self
    NoRealm: Self
    OnlyRealm: Self
    Special: Self

    def __init__(self, enctype: int | str | None): ...

@final
class KeySalt:
    enctype: EncryptionType
    salttype: SaltType

    def __init__(self, enctype: EncryptionType, salttype: SaltType | None): ...

@final
class KeySalts:
    keysalts: set[KeySalt]

    def __init__(self, keysalts: set[KeySalt]): ...

@final
class TlDataEntry:
    data_type: int
    contents: list[int]

@final
class TlData:
    entries: list[TlDataEntry]
