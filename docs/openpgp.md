---
layout: default
title: OpenPGP Profile (RFC 4880) for NeoPG
---
OpenPGP Profile (RFC 4880) for NeoPG
====================================

The following profile of RFC 4880 is used to aid the implementation of
NeoPG.  It deprecates underspecified features of OpenPG, avoids
ill-designed features and in general simplifies things to a tolerable
level.

4.2. Packet Headers

* The old packet format MUST be supported for input.
* The new packet format MUST be used for output.

4.2.1. Old Format Packet Lengths

* Packets with indeterminate length MUST be rejected.

4.3. Packet Tags

5.2.3.18. Preferred Key Server

* Preferred Key Server Packets MUST not be generatd.
* Preferred Key Server Packets MUST be ignored.

NOTE: Preferred key servers have not seen wide adoption, and they can
be used to violate the privacy of the recipient.  The standard allows
to set multiple preferred key servers on multiple user ids, which is
ambiguous.  The meaning of the URI in the field is left open to
interpretation.  Thus, existing preferred key servers in signature and
in user id signatures must be ignored and new ones must not be
generated.


5.7. Symmetrically Encrypted Data Packet

* Symmetrically Encrypted Data Packets MUST not be generated.
* Symmetrically Encrypted Data Packets MUST be rejected.

c.f. 5.13.

5.8. Marker Packet

* Marker Packets MUST NOT be generated.

5.9. Literal Data Packet

* Generated Literal Data Packets MUST have data type 'b' (binary).
* Generated Literal Data Packets MUST have a zero-length file name.
* Generated Literal Data Packets MUST have a timestamp of 0.
* All Literal Data Packets MUST be treated as if the data type is 'b' (binary).
* All Literal Data Packets MUST be treated as if the file name is zero-length.
* All Literal Data Packets MUST be treated as if the timestamp is 0.

5.10 Trust Packet

(To be specified)

5.11 User ID Packet

* Generated User ID Packets MUST have a payload less than or equal to 2 KB.
* User ID Packets larger than 2 KB and their certificates MUST be rejected.

NOTE: In the future, NeoPG will be strict about what a User ID Packet can
contain.  Preferably, it will only contain a (verifiable) email
address, a (verifiable) twitter handle, or some other handle supported
by a trust agency such as keybase.io.  Non-verifiable User ID Packets
will be usable after manual confirmation only.

5.12 User Attribute Packet

* User Attribute Packets MUST NOT be generated.
* All User Attribute Packets and its certificates MUST be ignored.

5.12.1 Image Attribute Subpacket

See 5.12.

6. Radix-64 Conversions

* Radix-64 MUST NOT be generated.

NOTE: Use Base64 instead if you need an ASCII transport.

7. Cleartext Signature Framework

* Cleartext signatures MUST NOT be generated.
* Cleartext signatures MUST be ignored.

NOTE: Use a detached signature instead.



* Limit the size of all packets

/* Maximum length of packets to avoid excessive memory allocation.  */
#define MAX_KEY_PACKET_LENGTH     (256 * 1024)
#define MAX_COMMENT_PACKET_LENGTH ( 64 * 1024)
#define MAX_ATTR_PACKET_LENGTH    ( 16 * 1024*1024)
