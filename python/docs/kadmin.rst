kadmin
======

.. py:module:: kadmin

.. py:class:: KAdminApiVersion

   kadm5 API version

   MIT krb5 supports up to version 4. Heimdal supports up to version 2.

   This changes which fields will be available in the Policy and Principal structs. If the version
   is too low, some fields may not be populated. We try our best to document those in the fields
   documentation themselves.

   If no version is provided during the KAdmin initialization, it defaults to the most conservative
   one, currently version 2.

   .. py:attribute:: Version2

      Version 2

      :type: KAdminApiVersion

   .. py:attribute:: Version3

      Version 3

      :type: KAdminApiVersion

   .. py:attribute:: Version4

      Version 4

      :type: KAdminApiVersion

.. py:class:: KAdmin

   Interface to kadm5
   
   This class has no constructor. Instead, use the `with_` methods

   .. py:staticmethod:: with_password(client_name, password, params=None, db_args=None, api_version=None)

      Construct a KAdmin object using a password
      
      :param client_name: client name, usually a principal name
      :type client_name: str
      :param password: password to authenticate with
      :type password: str
      :param params: additional kadm5 config options
      :type params: Params | None
      :param db_args: additional database specific arguments
      :type db_args: DbArgs | None
      :param api_version: kadm5 API version to use
      :type api_version: KAdminApiVersion | None
      :return: an initialized :py:class:`KAdmin` object
      :rtype: KAdmin
      
      .. code-block:: python
      
         kadm = KAdmin.with_password("user@EXAMPLE.ORG", "vErYsEcUrE")

   .. py:staticmethod:: with_keytab(client_name=None, keytab=None, params=None, db_args=None)

      Construct a KAdmin object using a keytab
      
      :param client_name: client name, usually a principal name. If not provided,
          `host/hostname` will be used
      :type client_name: str | None
      :param keytab: path to the keytab to use. If not provided, the default keytab will be
          used
      :type keytab: str | None
      :param params: additional kadm5 config options
      :type params: Params | None
      :param db_args: additional database specific arguments
      :type db_args: DbArgs | None
      :param api_version: kadm5 API version to use
      :type api_version: KAdminApiVersion | None
      :return: an initialized :py:class:`KAdmin` object
      :rtype: KAdmin

   .. py:staticmethod:: with_ccache(client_name=None, ccache_name=None, params=None, db_args=None)

      Construct a KAdmin object using a credentials cache
      
      :param client_name: client name, usually a principal name. If not provided, the default
          principal from the credentials cache will be used
      :type client_name: str | None
      :param ccache_name: credentials cache name. If not provided, the default credentials
          cache will be used
      :type ccache_name: str | None
      :param params: additional kadm5 config options
      :type params: Params | None
      :param db_args: additional database specific arguments
      :type db_args: DbArgs | None
      :param api_version: kadm5 API version to use
      :type api_version: KAdminApiVersion | None
      :return: an initialized :py:class:`KAdmin` object
      :rtype: KAdmin

   .. py:staticmethod:: with_anonymous(client_name, params=None, db_args=None)

      Not implemented

   .. py:method:: add_principal(name, **kwargs)

      Create a principal

      :param name: the name of the principal to create
      :type name: str
      :param kwargs: Extra args for the creation. The name of those arguments must match the
          attributes name of the :py:class:`Principal` class that are not marked as read-only.
          Same goes for their types.
      :return: the newly created :py:class:`Principal`
      :rtype: Principal

      In addition, the following arguments are available

      :param db_args: database specific arguments
      :type db_args: DbArgs
      :param key: how to set the principal key
      :type key: NewPrincipalKey
      :param keysalts: Use the specified keysalt list for setting the keys of the principal
      :type keysalts: KeySalts

   .. py:method:: rename_principal(old_name, new_name)

      Rename a principal

      :param old_name: the current name of the principal
      :type old_name: str
      :param new_name: the new name of the principal
      :type old_name: str

   .. py:method:: delete_principal(name)

      Delete a principal
      
      :py:meth:`Principal.delete` is also available
      
      :param name: name of the principal to delete
      :type name: str

   .. py:method:: get_principal(name)

      Retrieve a principal
      
      :param name: principal name to retrieve
      :type name: str
      :return: :py:class:`Principal` if found, None otherwise
      :rtype: Principal | None

   .. py:method:: principal_exists(name)

      Check if a principal exists
      
      :param name: principal name to check for
      :type name: str
      :return: `True` if the principal exists, `False` otherwise
      :rtype: bool

   .. py:method:: principal_change_password(name, password, keepold=None, keysalts=None)

      Change the password of a principal
      
      :py:meth:`Principal.change_password` is also available
      
      :param name: name of the principal to change the password of
      :type name: str
      :param password: the new password
      :type password: str
      :param keepold: Keeps the existing keys in the database. This flag is usually not necessary except
         perhaps for krbtgt principals. Defaults to false
      :type keepold: bool | None
      :param keysalts: Uses the specified keysalt list for setting the keys of the principal
      :type keysalts: KeySalts | None

   .. py:method:: principal_randkey(name, keepold=None, keysalts=None)

      Sets the key of the principal to a random value
      
      :py:meth:`Principal.randkey` is also available
      
      :param name: name of the principal to randomize the key of
      :type name: str
      :param keepold: Keeps the existing keys in the database. This flag is usually not necessary except
         perhaps for krbtgt principals. Defaults to false
      :type keepold: bool | None
      :param keysalts: Uses the specified keysalt list for setting the keys of the principal
      :type keysalts: KeySalts | None

   .. py:method:: list_principals(query=None)

      List principals
      
      :param query: a shell-style glob expression that can contain the wild-card characters
          `?`, `*`, and `[]`. All principal names matching the expression are retuned. If
          the expression does not contain an `@` character, an `@` character followed by
          the local realm is appended to the expression. If no query is provided, all
          principals are returned.
      :type query: str, optional
      :return: the list of principal names matching the query
      :rtype: list[str]

   .. py:method:: add_policy(name, **kwargs)

      Create a policy
      
      :param name: the name of the policy to create
      :type name: str
      :param kwargs: Extra args for the creation. The name of those arguments must match the
          attributes name of the :py:class:`Policy` class. Same goes for their types.
      :return: the newly created :py:class:`Policy`
      :rtype: Policy

   .. py:method:: delete_policy(name)

      Delete a policy
      
      :py:meth:`Policy.delete` is also available
      
      :param name: name of the policy to delete
      :type name: str

   .. py:method:: get_policy(name)

      Retrieve a policy
      
      :param name: policy name to retrieve
      :type name: str
      :return: :py:class:`Policy` if found, None otherwise
      :rtype: Policy | None

   .. py:method:: policy_exists(name)

      Check if a policy exists
      
      :param name: policy name to check for
      :type name: str
      :return: `True` if the policy exists, `False` otherwise
      :rtype: bool

   .. py:method:: list_policies(query=None)

      List policies
      
      :param query: a shell-style glob expression that can contain the wild-card characters
          `?`, `*`, and `[]`. All policy names matching the expression are returned.
          If no query is provided, all existing policy names are returned.
      :type query: str | None
      :return: the list of policy names matching the query
      :rtype: list[str]

.. py:class:: Principal

   .. py:attribute:: name

      Principal name

      :type: str

   .. py:attribute:: expire_time

      When the principal expires

      :type: datetime.datetime | None

   .. py:attribute:: last_password_change

      When the password was last changed

      Read-only

      :type: datetime.datetime | None

   .. py:attribute:: password_expiration

      When the password expires

      :type: datetime.datetime | None

   .. py:attribute:: max_life

      Maximum ticket life

      :type: datetime.timedelta | None

   .. py:attribute:: modified_by

      Last principal to modify this principal

      Read-only

      :type: str

   .. py:attribute:: modified_at

      When the principal was last modified

      Read-only

      :type: datetime.datetime | None

   .. py:attribute:: attributes

      See :py:class:`PrincipalAttributes`

      :type: PrincipalAttributes

   .. py:attribute:: kvno

      Current key version number

      Read-only, but can be set on principal creation

      :type: int

   .. py:attribute:: mkvno

      Master key version number

      Read-only

      :type: int

   .. py:attribute:: policy

      Associated policy

      :type: str | None

   .. py:attribute:: aux_attributes

      Extra attributes

      :type: int

   .. py:attribute:: max_renewable_life

      Maximum renewable ticket life

      :type: datetime.timedelta | None

   .. py:attribute:: last_success

      When the last successful authentication occurred

      Read-only

      :type: datetime.datetime | None

   .. py:attribute:: last_failed

      When the last failed authentication occurred

      Read-only

      :type: datetime.datetime | None

   .. py:attribute:: fail_auth_count

      Number of failed authentication attempts

      :type: int

   .. py:attribute:: tl_dats

      TL-data

      :type: TlData

   .. py:method:: modify(kadmin, **kwargs)

      Change this principal
      
      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin
      :param kwargs: Attributes to change. The name of those arguments must match the
          attributes name of the :py:class:`Principal` class that are not marked as read-only.
          Same goes for their types
      :return: a new :py:class:`Principal` object with the modifications made to it. The old
         object is still available, but will not be up-to-date
      :rtype: Principal

   .. py:method:: delete(kadmin)

      Delete this principal
      
      The object will still be available, but shouldn’t be used for modifying, as the policy
      may not exist anymore

      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin

   .. py:method:: change_password(kadmin, password, keepold=None, keysalts=None)

      Change the password of the principal

      Note that principal data will have changed after this, so you may need to refresh it
      
      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin
      :param password: the new password
      :type password: str
      :param keepold: Keeps the existing keys in the database. This flag is usually not necessary except
         perhaps for krbtgt principals. Defaults to false
      :type keepold: bool | None
      :param keysalts: Uses the specified keysalt list for setting the keys of the principal
      :type keysalts: KeySalts | None

   .. py:method:: randkey(kadmin, keepold=None, keysalts=None)

      Sets the key of the principal to a random value

      Note that principal data will have changed after this, so you may need to refresh it
      
      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin
      :param keepold: Keeps the existing keys in the database. This flag is usually not necessary except
         perhaps for krbtgt principals. Defaults to false
      :type keepold: bool | None
      :param keysalts: Uses the specified keysalt list for setting the keys of the principal
      :type keysalts: KeySalts | None

   .. py:method:: unlock(kadmin)

      Unlocks a locked principal (one which has received too many failed authentication attempts without
      enough time between them according to its password policy) so that it can successfully authenticate

      Note that principal data will have changed after this, so you may need to refresh it
      
      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin

.. py:class:: PrincipalAttributes(bits)

   Attributes set on a principal

   See `man kadmin(1)`, under the `add_principal` section for an explanation

   :param bits: Attributes bits
   :type bits: int

   .. py:attribute:: DisallowPostdated

      Prohibits the principal from obtaining postdated tickets

      :type: PrincipalAttributes

   .. py:attribute:: DisallowForwardable

      Prohibits the principal from obtaining forwardable tickets

      :type: PrincipalAttributes

   .. py:attribute:: DisallowTgtBased

      Specifies that a Ticket-Granting Service (TGS) request for a service ticket for the principal is not permitted

      :type: PrincipalAttributes

   .. py:attribute:: DisallowRenewable

      Prohibits the principal from obtaining renewable tickets

      :type: PrincipalAttributes

   .. py:attribute:: DisallowProxiable

      Prohibits the principal from obtaining proxiable tickets

      :type: PrincipalAttributes

   .. py:attribute:: DisallowDupSkey

      Disables user-to-user authentication for the principal by prohibiting this principal from obtaining a session key for another user

      :type: PrincipalAttributes

   .. py:attribute:: DisallowAllTix

      Forbids the issuance of any tickets for the principal

      :type: PrincipalAttributes

   .. py:attribute:: RequiresPreAuth

      Requires the principal to preauthenticate before being allowed to kinit

      :type: PrincipalAttributes

   .. py:attribute:: RequiresHwAuth

      Requires the principal to preauthenticate using a hardware device before being allowed to kinit

      :type: PrincipalAttributes

   .. py:attribute:: RequiresPwChange

      Force a password change

      :type: PrincipalAttributes

   .. py:attribute:: DisallowSvr

      Prohibits the issuance of service tickets for the principal

      :type: PrincipalAttributes

   .. py:attribute:: PwChangeService

      Marks the principal as a password change service principal

      :type: PrincipalAttributes

   .. py:attribute:: SupportDesMd5

      An AS_REQ for a principal with this bit set and an encrytion type of ENCTYPE_DES_CBC_CRC causes the encryption type ENCTYPE_DES_CBC_MD5 to be used instead

      :type: PrincipalAttributes

   .. py:attribute:: NewPrinc

      Allow kadmin administrators with `add` acls to modify the principal until this bit is cleared

      :type: PrincipalAttributes

   .. py:attribute:: OkAsDelegate

      Sets the OK-AS-DELEGATE flag on tickets issued for use with the principal as the service, which clients may use as a hint that credentials can and should be delegated when authenticating to the service

      :type: PrincipalAttributes

   .. py:attribute:: OkToAuthAsDelegate

      Sets the service to allow the use of S4U2Self

      :type: PrincipalAttributes

   .. py:attribute:: NoAuthDataRequired

      Prevents PAC or AD-SIGNEDPATH data from being added to service tickets for the principal

      :type: PrincipalAttributes

   .. py:attribute:: LockdownKeys

      Prevents keys for the principal from being extracted or set to a known value by the kadmin protocol

      :type: PrincipalAttributes

.. py:class:: NewPrincipalKey

   Method to use to set the principal key when creating it

   Passing the class itself is not enough. An object should be created from those subclasses.

   .. py:class:: Password(password)

      Provide a password to use

      :type password: str

   .. py:class:: NoKey()

      No key should be set on the principal

   .. py:class:: RandKey()

      A random key should be generated for the principal. Tries `ServerRandKey` and falls back to `OldStyleRandKey`

   .. py:class:: ServerRandKey()

      A random key should be generated for the principal by the server

   .. py:class:: OldStyleRandKey()

      Old-style random key. Creates the principal with KRB5_KDB_DISALLOW_ALL_TIX and a generated dummy key, then calls randkey on the principal and finally removes KRB5_KDB_DISALLOW_ALL_TIX

.. py:class:: Policy

   .. py:attribute:: name

      The policy name

      :type: str

   .. py:attribute:: password_min_life

      Minimum lifetime of a password

      :type: datetime.timedelta | None

   .. py:attribute:: password_max_life

      Maximum lifetime of a password

      :type: datetime.timedelta | None

   .. py:attribute:: password_min_length

      Minimum length of a password

      :type: int

   .. py:attribute:: password_min_classes

      Minimum number of character classes required in a password. The five character classes are
      lower case, upper case, numbers, punctuation, and whitespace/unprintable characters

      :type: int

   .. py:attribute:: password_history_num

      Number of past keys kept for a principal. May not be filled if used with other database
      modules such as the MIT krb5 LDAP KDC database module

      :type: int

   .. py:attribute:: policy_refcnt

      How many principals use this policy. Not filled for at least MIT krb5

      :type: int

   .. py:attribute:: password_max_fail

      Number of authentication failures before the principal is locked. Authentication failures
      are only tracked for principals which require preauthentication. The counter of failed
      attempts resets to 0 after a successful attempt to authenticate. A value of 0 disables
      lock‐out

      Only available in :py:class:`version<KAdminApiVersion>` 3 and above

      :type: int

   .. py:attribute:: password_failcount_interval

      Allowable time between authentication failures. If an authentication failure happens after
      this duration has elapsed since the previous failure, the number of authentication failures
      is reset to 1. A value of `None` means forever

      Only available in :py:class:`version<KAdminApiVersion>` 3 and above

      :type: datetime.timedelta | None

   .. py:attribute:: password_lockout_duration

      Duration for which the principal is locked from authenticating if too many authentication
      failures occur without the specified failure count interval elapsing. A duration of `None`
      means the principal remains locked out until it is administratively unlocked

      Only available in :py:class:`version<KAdminApiVersion>` 3 and above

      :type: datetime.timedelta | None

   .. py:attribute:: attributes

      Policy attributes

      Only available in :py:class:`version<KAdminApiVersion>` 4 and above

      :type: int

   .. py:attribute:: max_life

      Maximum ticket life

      Only available in :py:class:`version<KAdminApiVersion>` 4 and above

      :type: datetime.timedelta | None

   .. py:attribute:: max_renewable_life

      Maximum renewable ticket life

      Only available in :py:class:`version<KAdminApiVersion>` 4 and above

      :type: datetime.timedelta | None

   .. py:attribute:: allowed_keysalts

      Allowed keysalts

      Only available in :py:class:`version<KAdminApiVersion>` 4 and above

      :type: KeySalts | None

   .. py:attribute:: tl_data

      TL-data

      Only available in :py:class:`version<KAdminApiVersion>` 4 and above

      :type: TlData

   .. py:method:: modify(kadmin, **kwargs)

      Change this policy
      
      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin
      :param kwargs: Attributes to change. The name of those arguments must match the
          attributes name of the :py:class:`Policy` class. Same goes for their types. The
          `name` attribute is ignored.
      :return: a new :py:class:`Policy` object with the modifications made to it. The old
         object is still available, but will not be up-to-date
      :rtype: Policy

   .. py:method:: delete(kadmin)

      Delete this policy
      
      The object will still be available, but shouldn’t be used for modifying, as the policy
      may not exist anymore

      :param kadmin: A :py:class:`KAdmin` instance
      :type kadmin: KAdmin

.. py:class:: Params(realm=None, kadmind_port=None, kpasswd_port=None, admin_server=None, dbname=None, acl_file=None, dict_file=None, stash_file=None)

   kadm5 config options
   
   :param realm: Default realm database
   :type realm: str | None
   :param kadmind_port: kadmind port to connect to
   :type kadmind_port: int | None
   :param kpasswd_port: kpasswd port to connect to
   :type kpasswd_port: int | None
   :param admin_server: Admin server which kadmin should contact
   :type admin_server: str | None
   :param dbname: Name of the KDC database
   :type dbname: str | None
   :param acl_file: Location of the access control list file
   :type acl_file: str | None
   :param dict_file: Location of the dictionary file containing strings that are not allowed as passwords
   :type dict_file: str | None
   :param stash_file: Location where the master key has been stored
   :type stash_file: str | None
   
   .. code-block:: python
   
      params = Params(realm="EXAMPLE.ORG")

.. py:class:: DbArgs(/, *args, **kwargs)

   Database specific arguments
   
   See `man kadmin(1)` for a list of supported arguments
   
   :param \*args: Database arguments (without value)
   :type \*args: str
   :param \**kwargs: Database arguments (with or without value)
   :type \**kwargs: str | None
   
   .. code-block:: python
   
      db_args = DbArgs(host="ldap.example.org")

.. py:class:: EncryptionType(enctype)

   Kerberos encryption type

   :param enctype: Encryption type to convert from. Prefer using static attributes. See `man kdc.conf(5)` for a list of accepted values
   :type enctype: int | str

   .. py:attribute:: Des3CbcRaw

      Triple DES cbc mode raw (weak, deprecated)

      :type: EncryptionType

   .. py:attribute:: Des3CbcSha1

      Triple DES cbc mode with HMAC/sha1 (deprecated)

      :type: EncryptionType

   .. py:attribute:: ArcfourHmac

      ArcFour with HMAC/md5 (deprecated)

      :type: EncryptionType

   .. py:attribute:: ArcfourHmacExp

      Exportable ArcFour with HMAC/md5 (weak, deprecated)

      :type: EncryptionType

   .. py:attribute:: Aes128CtsHmacSha196

      AES-128 CTS mode with 96-bit SHA-1 HMAC

      :type: EncryptionType

   .. py:attribute:: Aes256CtsHmacSha196

      AES-256 CTS mode with 96-bit SHA-1 HMAC

      :type: EncryptionType

   .. py:attribute:: Camellia128CtsCmac

      Camellia-128 CTS mode with CMAC

      :type: EncryptionType

   .. py:attribute:: Camellia256CtsCmac

      Camellia-256 CTS mode with CMAC

      :type: EncryptionType

   .. py:attribute:: Aes128CtsHmacSha256128

      AES-128 CTS mode with 128-bit SHA-256 HMAC

      :type: EncryptionType

   .. py:attribute:: Aes256CtsHmacSha384192

      AES-256 CTS mode with 192-bit SHA-384 HMAC

      :type: EncryptionType

.. py:class:: SaltType(salttype)

   Kerberos salt type

   :param salttype: Salt type to convert from. Prefer using static attributes. See `man kdc.conf(5)` for a list of accepted values
   :type salttype: int | str | None

   .. py:attribute:: Normal

      Default for Kerberos Version 5

      :type: SaltType

   .. py:attribute:: NoRealm

      Same as the default, without using realm information

      :type: SaltType

   .. py:attribute:: OnlyRealm

      Uses only realm information as the salt

      :type: SaltType

   .. py:attribute:: Special

      Generate a random salt

      :type: SaltType

.. py:class:: KeySalt(enctype, salttype)

   Kerberos keysalt

   :param enctype: Encryption type
   :type enctype: EncryptionType
   :param salttype: Salt type
   :type salttype: SaltType

   .. py:attribute:: enctype

      Encryption type

      :type: EncryptionType

   .. py:attribute:: salttype

      Salt type

      :type: SaltType

.. py:class:: KeySalts(keysalts)

   Kerberos keysalt list

   :param keysalts: Keysalt list
   :type keysalts: set[KeySalt]

   .. py:attribute:: keysalts

      Keysalt list

      :type: set[KeySalt]

.. py:class:: TlDataEntry(data_type, contents)

   A single TL-data entry

   :param data_type: Entry type
   :type data_type: int
   :param contents: Entry contents
   :type contents: list[int]

   .. py:attribute:: data_type

      :type: int

   .. py:attribute:: contents

      :type: list[int]

.. py:class:: TlData(entries)

   TL-data entries

   :param entries: TL-data entries
   :type entries: list[TlDataEntry]

   .. py:attribute:: entries

      :type: list[TlDataEntry]


Exceptions
----------

.. automodule:: kadmin.exceptions
   :members:
   :undoc-members:
   :imported-members:
