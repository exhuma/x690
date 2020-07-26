Glossary
========

.. glossary::

    ASN.1
        From `wikipedia
        <https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One>`_:
        Abstract Syntax Notation One is a standard and notation that describes
        rules and structures for representing, encoding, transmitting, and
        decoding data in telecommunications and computer networking.

        In **SNMP** ASN.1 is used to define the structure of messages sent
        across the network. SNMP used **BER** encoding.

    X.690
        X.690 defines the encoding rules for ASN.1 notation. It is the
        underlying standard used by SNMP. It's reference document can be found
        here: https://www.itu.int/rec/T-REC-X.690/en

        Apart from encoding rules, it also defines a set of core variable types
        like :py:class:`~puresnmp.x690.types.ObjectIdentifier`,
        :py:class:`~puresnmp.x690.types.Integer`).

    TLV
        Type Length Value (See
        https://en.wikipedia.org/wiki/Type-length-value)
