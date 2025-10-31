Welcome to python-kadmin-rs's documentation!
============================================

This is a Python interface to libkadm5.

For remote operations:

.. code-block:: python

   import kadmin

   princ = "user/admin@EXAMPLE.ORG"
   password = "vErYsEcUrE"
   kadm = kadmin.KAdmin.with_password(princ, password)
   print(kadm.list_principals("*"))

For local operations:

.. code-block:: python

   import kadmin

   kadm = kadmin.KAdmin.with_local()
   print(kadm.list_principals("*"))

This module consists of bindings to the `kadmin` Rust crate. It doesn't link
against libkadm5 directly, but instead loads if at runtime. You can find more
information about this process in `the Rust crate documentation`_.

.. _the Rust crate documentation: https://docs.rs/kadmin/latest/kadmin/

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   kadmin.rst
   exceptions.rst
   sys.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
