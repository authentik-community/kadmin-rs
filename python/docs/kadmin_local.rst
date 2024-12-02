kadmin_local
============

The only difference with the :py:mod:`kadmin` module is the `KAdmin.with_` methods used to construct the KAdmin object. As such, only the :py:mod:`kadmin` module is fully documented and this documentation only contains the addition of the specialized initialization method, but the other objects are still accessible from `kadmin_local`, like `kadmin_local.Params()`.

.. py:module:: kadmin_local

.. py:class:: KAdmin

   Interface to kadm5
   
   This class has no constructor. Instead, use the `with_` methods

   .. py:staticmethod:: with_local(params=None, db_args=None)

      Construct a :py:class:`KAdmin` object for local database manipulation.
      
      :param params: additional kadm5 config options
      :type params: :py:class:`Params<kadmin.Params>` | None
      :param db_args: additional database specific arguments
      :type db_args: :py:class:`DbArgs<kadmin.DbArgs>` | None
      :return: an initialized :py:class:`KAdmin` object
      :rtype: KAdmin
