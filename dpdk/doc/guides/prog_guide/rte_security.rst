..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2017,2020-2021 NXP



Security Library
================

The security library provides a framework for management and provisioning
of security protocol operations offloaded to hardware based devices. The
library defines generic APIs to create and free security sessions which can
support full protocol offload as well as inline crypto operation with
NIC or crypto devices. The framework currently only supports the IPsec, PDCP
and DOCSIS protocols and associated operations, other protocols will be added
in the future.

Design Principles
-----------------

The security library provides an additional offload capability to an existing
crypto device and/or ethernet device.

.. code-block:: console

               +---------------+
               | rte_security  |
               +---------------+
                 \            /
        +-----------+    +--------------+
        |  NIC PMD  |    |  CRYPTO PMD  |
        +-----------+    +--------------+

.. note::

    Currently, the security library does not support the case of multi-process.
    It will be updated in the future releases.

The supported offload types are explained in the sections below.

Inline Crypto
~~~~~~~~~~~~~

RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO:
The crypto processing for security protocol (e.g. IPsec) is processed
inline during receive and transmission on NIC port. The flow based
security action should be configured on the port.

Ingress Data path - The packet is decrypted in RX path and relevant
crypto status is set in Rx descriptors. After the successful inline
crypto processing the packet is presented to host as a regular Rx packet
however all security protocol related headers are still attached to the
packet. e.g. In case of IPsec, the IPsec tunnel headers (if any),
ESP/AH headers will remain in the packet but the received packet
contains the decrypted data where the encrypted data was when the packet
arrived. The driver Rx path check the descriptors and based on the
crypto status sets additional flags in the rte_mbuf.ol_flags field.

.. note::

    The underlying device may not support crypto processing for all ingress packet
    matching to a particular flow (e.g. fragmented packets), such packets will
    be passed as encrypted packets. It is the responsibility of application to
    process such encrypted packets using other crypto driver instance.

Egress Data path - The software prepares the egress packet by adding
relevant security protocol headers. Only the data will not be
encrypted by the software. The driver will accordingly configure the
tx descriptors. The hardware device will encrypt the data before sending the
packet out.

.. note::

    The underlying device may support post encryption TSO.

.. code-block:: console

          Egress Data Path
                 |
        +--------|--------+
        |  egress IPsec   |
        |        |        |
        | +------V------+ |
        | | SADB lookup | |
        | +------|------+ |
        | +------V------+ |
        | |   Tunnel    | |   <------ Add tunnel header to packet
        | +------|------+ |
        | +------V------+ |
        | |     ESP     | |   <------ Add ESP header without trailer to packet
        | |             | |   <------ Mark packet to be offloaded, add trailer
        | +------|------+ |            meta-data to mbuf
        +--------V--------+
                 |
        +--------V--------+
        |    L2 Stack     |
        +--------|--------+
                 |
        +--------V--------+
        |                 |
        |     NIC PMD     |   <------ Set hw context for inline crypto offload
        |                 |
        +--------|--------+
                 |
        +--------|--------+
        |  HW ACCELERATED |   <------ Packet Encryption and
        |        NIC      |           Authentication happens inline
        |                 |
        +-----------------+


Inline protocol offload
~~~~~~~~~~~~~~~~~~~~~~~

RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL:
The crypto and protocol processing for security protocol (e.g. IPsec)
is processed inline during receive and transmission.  The flow based
security action should be configured on the port.

Ingress Data path - The packet is decrypted in the RX path and relevant
crypto status is set in the Rx descriptors. After the successful inline
crypto processing the packet is presented to the host as a regular Rx packet
but all security protocol related headers are optionally removed from the
packet. e.g. in the case of IPsec, the IPsec tunnel headers (if any),
ESP/AH headers will be removed from the packet and the received packet
will contains the decrypted packet only. The driver Rx path checks the
descriptors and based on the crypto status sets additional flags in
``rte_mbuf.ol_flags`` field. The driver would also set device-specific
metadata in ``RTE_SECURITY_DYNFIELD_NAME`` field.
This will allow the application to identify the security processing
done on the packet.

.. note::

    The underlying device in this case is stateful. It is expected that
    the device shall support crypto processing for all kind of packets matching
    to a given flow, this includes fragmented packets (post reassembly).
    E.g. in case of IPsec the device may internally manage anti-replay etc.
    It will provide a configuration option for anti-replay behavior i.e. to drop
    the packets or pass them to driver with error flags set in the descriptor.

Egress Data path - The software will send the plain packet without any
security protocol headers added to the packet. The driver will configure
the security index and other requirement in tx descriptors.
The hardware device will do security processing on the packet that includes
adding the relevant protocol headers and encrypting the data before sending
the packet out. The software should make sure that the buffer
has required head room and tail room for any protocol header addition. The
software may also do early fragmentation if the resultant packet is expected
to cross the MTU size. The software should also make sure that L2 header contents
are updated with the final L2 header which is expected post IPsec processing as
the IPsec offload will only update L3 and above in egress path.


.. note::

    The underlying device will manage state information required for egress
    processing. E.g. in case of IPsec, the seq number will be added to the
    packet, however the device shall provide indication when the sequence number
    is about to overflow. The underlying device may support post encryption TSO.

.. code-block:: console

         Egress Data Path
                 |
        +--------|--------+
        |  egress IPsec   |
        |        |        |
        | +------V------+ |
        | | SADB lookup | |
        | +------|------+ |
        | +------V------+ |
        | |   Desc      | |   <------ Mark packet to be offloaded
        | +------|------+ |
        +--------V--------+
                 |
        +--------V--------+
        |    L2 Stack     |
        +--------|--------+
                 |
        +--------V--------+
        |                 |
        |     NIC PMD     |   <------ Set hw context for inline crypto offload
        |                 |
        +--------|--------+
                 |
        +--------|--------+
        |  HW ACCELERATED |   <------ Add tunnel, ESP header etc header to
        |        NIC      |           packet. Packet Encryption and
        |                 |           Authentication happens inline.
        +-----------------+


Lookaside protocol offload
~~~~~~~~~~~~~~~~~~~~~~~~~~

RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL:
This extends librte_cryptodev to support the programming of IPsec
Security Association (SA) as part of a crypto session creation including
the definition. In addition to standard crypto processing, as defined by
the cryptodev, the security protocol processing is also offloaded to the
crypto device.

Decryption: The packet is sent to the crypto device for security
protocol processing. The device will decrypt the packet and it will also
optionally remove additional security headers from the packet.
E.g. in case of IPsec, IPsec tunnel headers (if any), ESP/AH headers
will be removed from the packet and the decrypted packet may contain
plain data only.

.. note::

    In case of IPsec the device may internally manage anti-replay etc.
    It will provide a configuration option for anti-replay behavior i.e. to drop
    the packets or pass them to driver with error flags set in descriptor.

Encryption: The software will submit the packet to cryptodev as usual
for encryption, the hardware device in this case will also add the relevant
security protocol header along with encrypting the packet. The software
should make sure that the buffer has required head room and tail room
for any protocol header addition.

.. note::

    In the case of IPsec, the seq number will be added to the packet,
    It shall provide an indication when the sequence number is about to
    overflow.

.. code-block:: console

          Egress Data Path
                 |
        +--------|--------+
        |  egress IPsec   |
        |        |        |
        | +------V------+ |
        | | SADB lookup | |   <------ SA maps to cryptodev session
        | +------|------+ |
        | +------|------+ |
        | |      \--------------------\
        | |    Crypto   | |           |  <- Crypto processing through
        | |      /----------------\   |     inline crypto PMD
        | +------|------+ |       |   |
        +--------V--------+       |   |
                 |                |   |
        +--------V--------+       |   |  create   <-- SA is added to hw
        |    L2 Stack     |       |   |  inline       using existing create
        +--------|--------+       |   |  session      sym session APIs
                 |                |   |    |
        +--------V--------+   +---|---|----V---+
        |                 |   |   \---/    |   | <--- Add tunnel, ESP header etc
        |     NIC PMD     |   |   INLINE   |   |      header to packet.Packet
        |                 |   | CRYPTO PMD |   |      Encryption/Decryption and
        +--------|--------+   +----------------+      Authentication happens
                 |                                    inline.
        +--------|--------+
        |       NIC       |
        +--------|--------+
                 V

PDCP Flow Diagram
~~~~~~~~~~~~~~~~~

Based on 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA);
Packet Data Convergence Protocol (PDCP) specification

.. code-block:: c

        Transmitting PDCP Entity          Receiving PDCP Entity
                  |                                   ^
                  |                       +-----------|-----------+
                  V                       | In order delivery and |
        +---------|----------+            | Duplicate detection   |
        | Sequence Numbering |            |  (Data Plane only)    |
        +---------|----------+            +-----------|-----------+
                  |                                   |
        +---------|----------+            +-----------|----------+
        | Header Compression*|            | Header Decompression*|
        | (Data-Plane only)  |            |   (Data Plane only)  |
        +---------|----------+            +-----------|----------+
                  |                                   |
        +---------|-----------+           +-----------|----------+
        | Integrity Protection|           |Integrity Verification|
        | (Control Plane only)|           | (Control Plane only) |
        +---------|-----------+           +-----------|----------+
        +---------|-----------+            +----------|----------+
        |     Ciphering       |            |     Deciphering     |
        +---------|-----------+            +----------|----------+
        +---------|-----------+            +----------|----------+
        |   Add PDCP header   |            | Remove PDCP Header  |
        +---------|-----------+            +----------|----------+
                  |                                   |
                  +----------------->>----------------+


.. note::

    * Header Compression and decompression are not supported currently.

Just like IPsec, in case of PDCP also header addition/deletion, cipher/
de-cipher, integrity protection/verification is done based on the action
type chosen.

DOCSIS Protocol
~~~~~~~~~~~~~~~

The Data Over Cable Service Interface Specification (DOCSIS) support comprises
the combination of encryption/decryption and CRC generation/verification, for
use in a DOCSIS-MAC pipeline.

.. code-block:: c


               Downlink                       Uplink
               --------                       ------

            Ethernet frame                Ethernet frame
           from core network              to core network
                  |                              ^
                  ~                              |
                  |                              ~         ----+
                  V                              |             |
        +---------|----------+        +----------|---------+   |
        |   CRC generation   |        |  CRC verification  |   |
        +---------|----------+        +----------|---------+   |   combined
                  |                              |             > Crypto + CRC
        +---------|----------+        +----------|---------+   |
        |     Encryption     |        |     Decryption     |   |
        +---------|----------+        +----------|---------+   |
                  |                              ^             |
                  ~                              |         ----+
                  |                              ~
                  V                              |
             DOCSIS frame                  DOCSIS frame
            to Cable Modem               from Cable Modem

The encryption/decryption is a combination of CBC and CFB modes using either AES
or DES algorithms as specified in the DOCSIS Security Specification (from DPDK
lib_rtecryptodev perspective, these are RTE_CRYPTO_CIPHER_AES_DOCSISBPI and
RTE_CRYPTO_CIPHER_DES_DOCSISBPI).

The CRC is Ethernet CRC-32 as specified in Ethernet/[ISO/IEC 8802-3].

.. note::

    * The offset and length of data for which CRC needs to be computed are
      specified via the auth offset and length fields of the rte_crypto_sym_op.
    * Other DOCSIS protocol functionality such as Header Checksum (HCS)
      calculation may be added in the future.

MACSEC Protocol
~~~~~~~~~~~~~~~

Media Access Control security (MACsec) provides point-to-point security
on Ethernet links and is defined by IEEE standard 802.1AE.
MACsec secures an Ethernet link for almost all traffic,
including frames from the Link Layer Discovery Protocol (LLDP),
Link Aggregation Control Protocol (LACP),
Dynamic Host Configuration Protocol (DHCP),
Address Resolution Protocol (ARP),
and other protocols that are not typically secured on an Ethernet link
because of limitations with other security solutions.

.. code-block:: c

             Receive                                                Transmit
             -------                                                --------

         Ethernet frame                                          Ethernet frame
          from network                                           towards network
                |                                                      ^
                ~                                                      |
                |                                                      ~
                V                                                      |
    +-----------------------+      +------------------+      +-------------------------+
    | Secure Frame Verify   |      | Cipher Suite(SA) |      | Secure Frame Generation |
    +-----------------------+<-----+------------------+----->+-------------------------+
    | SecTAG + ICV remove   |      |  SECY   |   SC   |      | SecTAG + ICV Added      |
    +---+-------------------+      +------------------+      +-------------------------+
                |                                                      ^
                |                                                      |
                V                                                      |
        Packet to Core/App                                     Packet from Core/App



To configure MACsec on an inline NIC device or a lookaside crypto device,
a security association (SA) and a secure channel (SC) are created
before creating rte_security session.

SA is created using API ``rte_security_macsec_sa_create``
which allows setting SA keys, salt, SSCI, packet number (PN) into the PMD,
and the API returns a handle which can be used to map it with a secure channel,
using the API ``rte_security_macsec_sc_create``.
Same SAs can be used for multiple SCs.
The Rx SC will need a set of 4 SAs for each of the association numbers (AN).
For Tx SC a single SA is set which will be used by hardware to process the packet.

The API ``rte_security_macsec_sc_create`` returns a handle for SC,
and this handle is set in ``rte_security_macsec_xform``
to create a MACsec session using ``rte_security_session_create``.


Device Features and Capabilities
---------------------------------

Device Capabilities For Security Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The device (crypto or ethernet) capabilities which support security operations,
are defined by the security action type, security protocol, protocol
capabilities and corresponding crypto capabilities for security. For the full
scope of the Security capability see definition of rte_security_capability
structure in the *DPDK API Reference*.

.. code-block:: c

   struct rte_security_capability;

Each driver (crypto or ethernet) defines its own private array of capabilities
for the operations it supports. Below is an example of the capabilities for a
PMD which supports the IPsec and PDCP protocol.

.. code-block:: c

    static const struct rte_security_capability pmd_security_capabilities[] = {
        { /* IPsec Lookaside Protocol offload ESP Tunnel Egress */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_IPSEC,
                .ipsec = {
                        .proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
                        .mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
                        .direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
                        .options = { 0 }
                },
                .crypto_capabilities = pmd_capabilities
        },
        { /* IPsec Lookaside Protocol offload ESP Tunnel Ingress */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_IPSEC,
                .ipsec = {
                        .proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
                        .mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
                        .direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS,
                        .options = { 0 }
                },
                .crypto_capabilities = pmd_capabilities
        },
        { /* PDCP Lookaside Protocol offload Data Plane */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_PDCP,
                .pdcp = {
                        .domain = RTE_SECURITY_PDCP_MODE_DATA,
                        .capa_flags = 0
                },
                .crypto_capabilities = pmd_capabilities
        },
        { /* PDCP Lookaside Protocol offload Control */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_PDCP,
                .pdcp = {
                        .domain = RTE_SECURITY_PDCP_MODE_CONTROL,
                        .capa_flags = 0
                },
                .crypto_capabilities = pmd_capabilities
        },
	{ /* PDCP Lookaside Protocol offload short MAC-I */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_PDCP,
                .pdcp = {
                        .domain = RTE_SECURITY_PDCP_MODE_SHORT_MAC,
                        .capa_flags = 0
                },
                .crypto_capabilities = pmd_capabilities
        },
        {
                .action = RTE_SECURITY_ACTION_TYPE_NONE
        }
    };
    static const struct rte_cryptodev_capabilities pmd_capabilities[] = {
        {    /* SHA1 HMAC */
            .op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
            .sym = {
                .xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
                .auth = {
                    .algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
                    .block_size = 64,
                    .key_size = {
                        .min = 64,
                        .max = 64,
                        .increment = 0
                    },
                    .digest_size = {
                        .min = 12,
                        .max = 12,
                        .increment = 0
                    },
                    .aad_size = { 0 },
                    .iv_size = { 0 }
                }
            }
        },
        {    /* AES CBC */
            .op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
            .sym = {
                .xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
                .cipher = {
                    .algo = RTE_CRYPTO_CIPHER_AES_CBC,
                    .block_size = 16,
                    .key_size = {
                        .min = 16,
                        .max = 32,
                        .increment = 8
                    },
                    .iv_size = {
                        .min = 16,
                        .max = 16,
                        .increment = 0
                    }
                }
            }
        }
    }

Below is an example of the capabilities for a PMD which supports the DOCSIS
protocol.

.. code-block:: c

    static const struct rte_security_capability pmd_security_capabilities[] = {
        { /* DOCSIS Uplink */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_DOCSIS,
                .docsis = {
                        .direction = RTE_SECURITY_DOCSIS_UPLINK
                },
                .crypto_capabilities = pmd_capabilities
        },
        { /* DOCSIS Downlink */
                .action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_DOCSIS,
                .docsis = {
                        .direction = RTE_SECURITY_DOCSIS_DOWNLINK
                },
                .crypto_capabilities = pmd_capabilities
        },
        {
                .action = RTE_SECURITY_ACTION_TYPE_NONE
        }
    };
    static const struct rte_cryptodev_capabilities pmd_capabilities[] = {
        {    /* AES DOCSIS BPI */
            .op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
            .sym = {
                .xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
                .cipher = {
                    .algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI,
                    .block_size = 16,
                    .key_size = {
                        .min = 16,
                        .max = 32,
                        .increment = 16
                    },
                    .iv_size = {
                        .min = 16,
                        .max = 16,
                        .increment = 0
                    }
                }
            }
        },

        RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
    };

Below is the example PMD capability for MACsec

.. code-block:: c

    static const struct rte_security_capability pmd_security_capabilities[] = {
        {
                .action = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
                .protocol = RTE_SECURITY_PROTOCOL_MACSEC,
                .macsec = {
                        .mtu = 1500,
                        .alg = RTE_SECURITY_MACSEC_ALG_GCM_128,
                        .max_nb_sc = 64,
                        .max_nb_sa = 128,
                        .max_nb_sess = 64,
                        .replay_win_sz = 4096,
                        .relative_sectag_insert = 1,
                        .fixed_sectag_insert = 1,
                        .icv_include_da_sa = 1,
                        .ctrl_port_enable = 1,
                        .preserve_sectag = 1,
                        .preserve_icv = 1,
                        .validate_frames = 1,
                        .re_key = 1,
                        .anti_replay = 1,
                },
                .crypto_capabilities = NULL,
        },
    };

Capabilities Discovery
~~~~~~~~~~~~~~~~~~~~~~

Discovering the features and capabilities of a driver (crypto/ethernet)
is achieved through the ``rte_security_capabilities_get()`` function.

.. code-block:: c

   const struct rte_security_capability *rte_security_capabilities_get(uint16_t id);

This allows the user to query a specific driver and get all device
security capabilities. It returns an array of ``rte_security_capability`` structures
which contains all the capabilities for that device.

Security Session Create/Free
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Security Sessions are created to store the immutable fields of a particular Security
Association for a particular protocol which is defined by a security session
configuration structure which is used in the operation processing of a packet flow.
Sessions are used to manage protocol specific information as well as crypto parameters.
Security sessions cache this immutable data in a optimal way for the underlying PMD
and this allows further acceleration of the offload of Crypto workloads.

The Security framework provides APIs to create and free sessions for crypto/ethernet
devices, where sessions are mempool objects. It is the application's responsibility
to create and manage two session mempools - one for session and other for session
private data. The private session data mempool object size should be able to
accommodate the driver's private data of security session. The application can get
the size of session private data using API ``rte_security_session_get_size``.
And the session mempool object size should be enough to accommodate
``rte_security_session``.

Once the session mempools have been created, ``rte_security_session_create()``
is used to allocate and initialize a session for the required crypto/ethernet device.

Session APIs need a parameter ``rte_security_ctx`` to identify the crypto/ethernet
security ops. This parameter can be retrieved using the APIs
``rte_cryptodev_get_sec_ctx()`` (for crypto device) or ``rte_eth_dev_get_sec_ctx``
(for ethernet port).

Sessions already created can be updated with ``rte_security_session_update()``.

When a session is no longer used, the user must call ``rte_security_session_destroy()``
to free the driver private session data and return the memory back to the mempool.

For look aside protocol offload to hardware crypto device, the ``rte_crypto_op``
created by the application is attached to the security session by the API
``rte_security_attach_session()``.

For Inline Crypto and Inline protocol offload, device specific defined metadata is
updated in the mbuf using ``rte_security_set_pkt_metadata()`` if
``RTE_ETH_TX_OFFLOAD_SEC_NEED_MDATA`` is set.

.. note::

    In case of inline processed packets, ``RTE_SECURITY_DYNFIELD_NAME`` field
    would be used by the driver to relay information on the security processing
    associated with the packet. In ingress, the driver would set this in Rx
    path while in egress, ``rte_security_set_pkt_metadata()`` would perform a
    similar operation. The application is expected not to modify the field
    when it has relevant info. For ingress, this device-specific 64 bit value
    is required to derive other information (like userdata), required for
    identifying the security processing done on the packet.

Security session configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Security Session configuration structure is defined as ``rte_security_session_conf``

.. literalinclude:: ../../../lib/security/rte_security.h
   :language: c
   :start-after: Structure rte_security_session_conf 8<
   :end-before: >8 End of structure rte_security_session_conf.

The configuration structure reuses the ``rte_crypto_sym_xform`` struct for crypto related
configuration. The ``rte_security_session_action_type`` struct is used to specify whether the
session is configured for Lookaside Protocol offload or Inline Crypto or Inline Protocol
Offload.

.. literalinclude:: ../../../lib/security/rte_security.h
   :language: c
   :start-after: Enumeration of rte_security_session_action_type 8<
   :end-before: >8 End enumeration of rte_security_session_action_type.

The ``rte_security_session_protocol`` is defined as

.. literalinclude:: ../../../lib/security/rte_security.h
   :language: c
   :start-after: Enumeration of rte_security_session_protocol 8<
   :end-before: >8 End enumeration of rte_security_session_protocol.

Currently the library defines configuration parameters for IPsec and PDCP only.
For other protocols like MACSec, structures and enums are defined as place holders
which will be updated in the future.

IPsec related configuration parameters are defined in ``rte_security_ipsec_xform``

MACsec related configuration parameters are defined in ``rte_security_macsec_xform``

PDCP related configuration parameters are defined in ``rte_security_pdcp_xform``

DOCSIS related configuration parameters are defined in ``rte_security_docsis_xform``


Security API
~~~~~~~~~~~~

The rte_security Library API is described in the *DPDK API Reference* document.

Flow based Security Session
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the case of NIC based offloads, the security session specified in the
'rte_flow_action_security' must be created on the same port as the
flow action that is being specified.

The ingress/egress flow attribute should match that specified in the security
session if the security session supports the definition of the direction.

Multiple flows can be configured to use the same security session. For
example if the security session specifies an egress IPsec/MACsec SA, then multiple
flows can be specified to that SA. In the case of an ingress IPsec SA then
it is only valid to have a single flow to map to that security session.

.. code-block:: console

         Configuration Path
                 |
        +--------|--------+
        |    Add/Remove   |
        | IPsec/MACsec SA |   <------ Build security flow action of
        |        |        |           IPsec/MACsec transform
        |--------|--------|
                 |
        +--------V--------+
        |   Flow API      |
        +--------|--------+
                 |
        +--------V--------+
        |                 |
        |     NIC PMD     |   <------ Add/Remove SA to/from hw context
        |                 |
        +--------|--------+
                 |
        +--------|--------+
        |  HW ACCELERATED |
        |        NIC      |
        |                 |
        +--------|--------+

* Add/Delete IPsec SA flow:
  To add a new inline SA construct a rte_flow_item for Ethernet + IP + ESP
  using the SA selectors and the ``rte_security_ipsec_xform`` as the ``rte_flow_action``.
  Note that any rte_flow_items may be empty, which means it is not checked.

.. code-block:: console

    In its most basic form, IPsec flow specification is as follows:
        +-------+     +----------+    +--------+    +-----+
        |  Eth  | ->  |   IP4/6  | -> |   ESP  | -> | END |
        +-------+     +----------+    +--------+    +-----+

    However, the API can represent, IPsec crypto offload with any encapsulation:
        +-------+            +--------+    +-----+
        |  Eth  | ->  ... -> |   ESP  | -> | END |
        +-------+            +--------+    +-----+

* Add/Delete MACsec SA flow:
  To add a new inline SA construct a rte_flow_item for Ethernet + SecTAG
  using the SA selectors and the ``rte_security_macsec_xform`` as the ``rte_flow_action``.
  Note that any rte_flow_items may be empty, which means it is not checked.

.. code-block:: console

    In its most basic form, MACsec flow specification is as follows:
        +-------+     +----------+     +-----+
        |  Eth  | ->  |  SecTag  |  -> | END |
        +-------+     +----------+     +-----+

    However, the API can represent, MACsec offload with any encapsulation:
        +-------+            +--------+    +-----+
        |  Eth  | ->  ... -> | SecTag | -> | END |
        +-------+            +--------+    +-----+


Telemetry support
-----------------

The Security library has support for displaying Crypto device information
with respect to its Security capabilities. Telemetry commands that can be used
are shown below.

#. Get the list of available Crypto devices by ID, that supports Security features::

     --> /security/cryptodev/list
     {"/security/cryptodev/list": [0, 1, 2, 3]}

#. Get the security capabilities of a Crypto device::

     --> /security/cryptodev/sec_caps,0
	 {"/security/cryptodev/sec_caps": {"sec_caps": [<array of serialized bytes of
	 capabilities>], "sec_caps_n": <number of capabilities>}}

 #. Get the security crypto capabilities of a Crypto device::

     --> /security/cryptodev/crypto_caps,0,0
	 {"/security/cryptodev/crypto_caps": {"crypto_caps": [<array of serialized bytes of
	 capabilities>], "crypto_caps_n": <number of capabilities>}}

For more information on how to use the Telemetry interface, see
the :doc:`../howto/telemetry`.
