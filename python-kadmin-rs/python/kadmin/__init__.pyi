from typing import List, final
import datetime

__version__: str

@final
class KAdmin:
    def add_principal(self): ...
    def delete_principal(self): ...
    def modify_principal(self): ...
    def rename_principal(self): ...
    def get_principal(self, name: str) -> Principal | None: ...
    def principal_exists(self, name: str) -> bool: ...
    def list_principals(self, query: str | None = None) -> List[str]: ...
    def add_policy(self, name: str, **kwargs) -> Policy: ...
    def delete_policy(self, name: str) -> None: ...
    def get_policy(self, name: str) -> Policy | None: ...
    def policy_exists(self, name: str) -> bool: ...
    def list_policies(self, query: str | None = None) -> List[str]: ...
    @staticmethod
    def with_password(
        client_name: str,
        password: str,
        params: Params | None = None,
        db_args: DbArgs | None = None,
    ) -> KAdmin: ...
    @staticmethod
    def with_keytab(
        client_name: str | None = None,
        keytab: str | None = None,
        params: Params | None = None,
        db_args: DbArgs | None = None,
    ) -> KAdmin: ...
    @staticmethod
    def with_ccache(
        client_name: str | None = None,
        ccache_name: str | None = None,
        params: Params | None = None,
        db_args: DbArgs | None = None,
    ) -> KAdmin: ...
    @staticmethod
    def with_anonymous(
        client_name: str, params: Params | None = None, db_args: DbArgs | None = None
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
    tl_data: TlData

    def modify(self, **kwargs) -> Policy: ...
    def delete(self) -> None: ...

@final
class Principal:
    def change_password(self, password: str): ...

@final
class Params: ...

@final
class DbArgs: ...

@final
class TlDataEntry:
    data_type: int
    contents: list[int]

@final
class TlData:
    entries: list[TlDataEntry]
