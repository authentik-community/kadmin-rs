from typing import List, final

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
    def add_policy(self): ...
    def modify_policy(self): ...
    def delete_policy(self): ...
    def get_policy(self): ...
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
class Principal:
    def change_password(self, password: str): ...

@final
class Params: ...

@final
class DbArgs: ...
