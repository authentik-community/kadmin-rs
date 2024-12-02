Welcome to python-kadmin-rs's documentation!
============================================

This is a Python interface to libkadm5. It provides two Python modules: `kadmin` for remote operations, and `kadmin_local` for local operations.

With `kadmin`:

.. code-block:: python

   import kadmin

   princ = "user/admin@EXAMPLE.ORG"
   password = "vErYsEcUrE"
   kadm = kadmin.KAdmin.with_password(princ, password)
   print(kadm.list_principals("*"))

With `kadmin_local`:

.. code-block:: python

   import kadmin_local

   kadm = kadmin.KAdmin.with_local()
   print(kadm.list_principals("*"))

The only difference between the two modules is the `KAdmin.with_` methods used to construct the KAdmin object. As such, only the `kadmin` module is fully documented. The `kadmin_local` documentation only contains the addition of the specialized initialization method.

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   kadmin.rst
   kadmin_local.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
