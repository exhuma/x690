Glossary
========

.. glossary::

   ASN.1
      Abstract Syntax Notation One. A language that describes the structure
      of data independently of how it is encoded. SNMP, LDAP and X.509 define
      their messages in ASN.1.

   BER
      Basic Encoding Rules. The encoding rules of :term:`X.690` that x690
      implements. Every value is encoded as a :term:`TLV`.

   X.690
      The ITU-T recommendation that defines BER and its variants for
      :term:`ASN.1` data: https://www.itu.int/rec/T-REC-X.690/en

   TLV
      Type, length, value: the three parts of every BER encoded value. See
      https://en.wikipedia.org/wiki/Type-length-value

   Type class
      One of universal, application, context or private. Universal types are
      defined by the standard; the others by the protocol that uses them. See
      :class:`~x690.util.TypeClass`.

   Nature
      Primitive for a single value, constructed for a value that contains
      other values. See :class:`~x690.util.TypeNature`.

   Tag
      The number that identifies a type within its :term:`type class`.
