libkadm5 bindings
=================

Raw constants from libkadm5 are also available under the following modules:

* ``kadmin.sys.mit_client``
* ``kadmin.sys.mit_server``
* ``kadmin.sys.heimdal_client``
* ``kadmin.sys.heimdal_server``

The list of all constants is available in `the Rust crate documentation`_,
under the appropriate module and the `Constants` section.

.. _the Rust crate documentation: https://docs.rs/kadmin/latest/kadmin/sys/index.html

For example, the ``KRB5_KDB_REQUIRES_PRE_AUTH`` constant for MIT client-side can be used with

.. code-block:: python

   import kadmin

   print(kadmin.sys.mit_client.KRB5_KDB_REQUIRES_PRE_AUTH)
