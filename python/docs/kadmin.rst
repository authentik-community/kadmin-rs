kadmin
======

.. py:module:: kadmin

.. py:class:: KAdmin

   Interface to kadm5
   
   This class has no constructor. Instead, use the `with_` methods

   .. py:staticmethod:: with_password(client_name, password, params=None, db_args=None)

      Construct a KAdmin object using a password
      
      :param client_name: client name, usually a principal name
      :type client_name: str
      :param password: password to authenticate with
      :type password: str
      :param params: additional kadm5 config options
      :type params: Params | None
      :param db_args: additional database specific arguments
      :type db_args: DbArgs | None
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
      :return: an initialized :py:class:`KAdmin` object
      :rtype: KAdmin

   .. py:staticmethod:: with_anonymous(client_name, params=None, db_args=None)

      Not implemented

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
          attributes name of the :py:class:`Policy` class. Same goes for their types. The
          `name` attribute is ignored.
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

   .. py:method:: change_password(password)

      Change the password of the principal
      
      :param password: the new password
      :type password: str

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

      :type: int

   .. py:attribute:: password_failcount_interval

      Allowable time between authentication failures. If an authentication failure happens after
      this duration has elapsed since the previous failure, the number of authentication failures
      is reset to 1. A value of `None` means forever

      :type: datetime.timedelta | None

   .. py:attribute:: password_lockout_duration

      Duration for which the principal is locked from authenticating if too many authentication
      failures occur without the specified failure count interval elapsing. A duration of `None`
      means the principal remains locked out until it is administratively unlocked

      :type: datetime.timedelta | None

   .. py:attribute:: attributes

      Policy attributes

      :type: int

   .. py:attribute:: max_life

      Maximum ticket life

      :type: datetime.timedelta | None

   .. py:attribute:: max_renewable_life

      Maximum renewable ticket life

      :type: datetime.timedelta | None

   .. py:attribute:: allowed_keysalts

      Allowed keysalts

      :type: KeySaltList | None

   .. py:attribute:: tl_data

      TL-data

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

.. py:class:: KeySaltList(keysalts)

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
