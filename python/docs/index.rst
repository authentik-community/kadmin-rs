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

   import kadmin

   kadm = kadmin.KAdmin.with_local()
   print(kadm.list_principals("*"))

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
