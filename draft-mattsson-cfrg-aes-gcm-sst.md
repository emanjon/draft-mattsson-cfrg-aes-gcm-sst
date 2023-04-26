---
title: "Galois Counter Mode with Secure Short Tags (GCM-SST)"
abbrev: "GCM-SST"
category: info

docname: draft-mattsson-cfrg-aes-gcm-sst-latest
submissiontype: IRTF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "emanjon/draft-mattsson-cfrg-aes-gcm-sst"
  latest: "https://emanjon.github.io/draft-mattsson-cfrg-aes-gcm-sst/draft-mattsson-cfrg-aes-gcm-sst.html"

author:
- initials: J.
  surname: Preuß Mattsson
  name: John Preuß Mattsson
  org: Ericsson AB
  abbrev: Ericsson
  country: Sweden
  email: john.mattsson@ericsson.com
- initials: M.
  surname: Campagna
  name: Matthew Campagna
  org: University of Waterloo
  country: Canada
  email: mcampagna@gmail.com

normative:

  RFC5116:
  RFC8452:

  AES:
    target: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
    title: "ADVANCED ENCRYPTION STANDARD (AES)"
    seriesinfo:
      "NIST": "Federal Information Processing Standards Publication 197"
    date: November 2001

informative:

  RFC3711:
  I-D.ietf-sframe-enc:

  MoQ:
    target: https://datatracker.ietf.org/wg/moq/about/
    title: "Media Over QUIC"
    author:
      -
        ins: IETF
    date: September 2022

  GCM:
    target: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    seriesinfo:
      "NIST": "Special Publication 800-38D"
    author:
      -
        ins: M. Dworkin
    date: November 2007

  Ferguson:
    target: https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/Comments/CWC-GCM/Ferguson2.pdf
    title: "Authentication weaknesses in GCM"
    author:
      -
        ins: N. Ferguson
    date: May 2005

  Nyberg:
    target: https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/Comments/general-comments/papers/Nyberg_Gilbert_and_Robshaw.pdf
    title: "Galois MAC with forgery probability close to ideal"
    author:
      -
        ins: K. Nyberg
      -
        ins: H. Gilbert
      -
        ins: M. Robshaw
    date: June 2005

  Mattsson:
    target: https://eprint.iacr.org/2015/477.pdf
    title: "Authentication Key Recovery on Galois/Counter Mode (GCM)"
    author:
      -
        ins: J. Mattsson
      -
        ins: M. Westerlund
    date: May 2015

--- abstract

This document defines the Galois Counter Mode with Secure Short Tags (GCM-SST) Authenticated Encryption with Associated Data (AEAD) algorithm. GCM-SST can be used with any keystream generator, not just a block cipher. The two main differences compared to GCM is that GCM-SST uses an additional subkey Q and that new subkeys H and Q are derived for each nonce. This enables short tags with forgery probabilities close to ideal. This document also registers several instances of Advanced Encryption Standard (AES) with Galois Counter Mode with Secure Short Tags (AES-GCM-SST).

This document is the product of the Crypto Forum Research Group.

--- middle

# Introduction

Advanced Encryption Standard (AES) in Galois Counter Mode (AES-GCM) {{GCM}} is a widely used AEAD algorithm {{RFC5116}} due to its attractive performance in both software and hardware as well as its provable security. During the NIST standardization, Ferguson pointed out two weaknesses in the GCM authentication function {{Ferguson}}. The weaknesses are especially concerning when GCM is used with short tags. The first weakness significantly increases the probability of successful forgery. The second weakness reveals the subkey H if the attacker manages to create successful forgeries. With knowledge of the subkey H, the attacker always succeeds with subsequent forgeries. The probability of multiple successful forgeries is therefore significantly increased.

As a comment to NIST, Nyberg et al. {{Nyberg}} explained how small changes based on proven theoretical constructions mitigate the weaknesses. Unfortunately, NIST did not follow the advice from Nyberg et al. and instead specified additional requirements for use with short tags in Appendix C of {{GCM}}. NIST did not give any motivations for the specific choice of parameters, or for that matter the security levels they were assumed to give. As shown by Mattsson et al. {{Mattsson}}, feedback of successful or unsuccessful forgery attempts is almost always possible, contradicting NIST's assumptions for short tags. NIST also appears to have used non-optimal attacks to calculate the parameters.

32-bit tags are standard in most radio link layers including 5G, 64-bit tags are very common in transport and application layers of the Internet of Things, and 32-, 64-, and 80-bit tags are common in media-encryption applications. Audio packets are small, numerous, and ephemeral, so on the one hand, they are very sensitive in percentage terms to crypto overhead, and on the other hand, forgery of individual packets is not a big concern. Due to its weaknesses, GCM is typically not used with short tags. The result is decreased performance from larger than needed tags {{MoQ}}, or decreased performance from using much slower constructions such as AES-CTR combined with HMAC {{RFC3711}}{{I-D.ietf-sframe-enc}}.

This document defines the Galois Counter Mode with Secure Short Tags (GCM-SST) Authenticated Encryption with Associated Data (AEAD) algorithm following the recommendations from Nyberg et al. {{Nyberg}}. GCM-SST is defined with a general interface so that it can be used with any keystream generator, not just a 128-bit block cipher. The two main differences compared to GCM {{GCM}} is that GCM-SST uses an additional subkey Q and that new subkeys H and Q are derived for each nonce. This enables short tags with forgery probability close to ideal. See Section {{GCM-SST}}.

This document also registers several instances of Advanced Encryption Standard (AES) with Galois Counter Mode with Secure Short Tags (AES-GCM-SST) where where AES {{AES}} in counter mode is used as the keystream generator. See Section {{AES-GCM-SST}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Galois Counter Mode with Secure Short Tags {#GCM-SST}

This section defines the Galois Counter Mode with Secure Short Tags (GCM-SST) AEAD algorithm following the recommendations from Nyberg et al. {{Nyberg}}. GCM-SST is defined with a general interface so that it can be used with any keystream generator, not just a 128-bit block cipher. The two main differences compared to GCM {{GCM}} is that GCM-SST uses an additional subkey Q and that new subkeys H and Q are derived for each nonce. This enables short tags with forgery probability close to ideal.

GCM-SST adheres to an AEAD interface {{RFC5116}} and the encryption function takes four variable-length octet string parameters. A secret key K, a nonce N, a plaintext P, and the associated data A. The keystream generator is instantiated with K and N. The keystream MUST NOT depend on P and A. The minimum and maximum length of all parameters depends on the keystream generator. The keystream generator produces a keystream Z consisting of 128-bit chunks where z[1] is the first chunk. The first three chunks z[1], z[2], and z[3] are used as the three subkeys H, Q, and M. The following keystream chunks are used to encrypt the plaintext. Instead of GHASH {{GCM}}, GCM-SST makes use of the POLYVAL function {{RFC8452}}, which results in more efficient software implementations on little-endian architectures. The subkeys H and Q are field elements used in POLYVAL while the subkey M is used for the final masking of the tag.

## Encryption

Input:

* Key K (variable-length octet string)
* Nonce N (variable-length octet string)
* Associated data A (variable-length octet string)
* Plaintext P (variable-length octet string)

Output:

* Ciphertext ct (variable-length octet string)
* Tag tag (octet string with length tag_length)

Steps:

1. Initate keystream generator with K and N
2. H = Z[1], Q = Z[2], M = Z[3]
3. ct = P XOR trim(Z[4, n + 3], len(P))
4. S = zeropad(A) \|\| zeropad(ct) \|\| uint64(len(A)) \|\| uint64(len(ct))
5. X = POLYVAL(H, S[1], S[2], ..., S[m + n - 1])
6. full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
7. tag = trim(full_tag, tag_length)
8. return (ct, tag)

where

* = is the assignment operator
* trim(x, y) truncates an octet string x to y octets
* len(x) returns the length of the octet string x
* zeropad(x) right pads an octet string x to a multiple of 16 bytes
* n is the number of 128-bit chunks in zeropad(P)
* m is the number of 128-bit chunks in zeropad(A)
* \|\| is concatenation of octet strings
* uint64(x) encodes an integer x as a little endian uint64
* POLYVAL is defined in RFC 8452
* XOR is the bitwise exclusive OR operation

## Decryption

Input:

* Key K (variable-length octet string)
* Nonce N (variable-length octet string)
* Associated data A (variable-length octet string)
* Ciphertext ct (variable-length octet string)
* Tag tag (octet string with length tag_length)

Output:

* Plaintext P (variable-length octet string) or "verification failed" error

Steps:

1. Initate keystream generator with K and N
2. Let H = Z[1], Q = Z[2], M = Z[3]
3. Let S = zeropad(A) \|\| zeropad(ct) \|\| uint64(len(A)) \|\| uint64(len(ct))
4. X = POLYVAL(H, S[1], S[2], ..., S[m + n - 1])
5. T = POLYVAL(Q, X XOR S[m + n]) XOR M
6. expected_tag = trim(T, tag_length)
7. Let P = ct XOR trim( Z[4, n + 3], len(ct) )
8. If tag == expected_tag, then return P; else return "verification failed" error.

## Encoding (ct, tag) Tuples

Applications MAY keep the ciphertext and the authentication tag in distinct structures or encode both as a single string C. In the latter case, the tag MUST immediately follow the ciphertext ct:

C = ct \|\| tag

# AES with Galois Counter Mode with Secure Short Tags {#AES-GCM-SST}

When GCM-SSM is instanciated with AES {{AES}}, then the keystream generator is AES in counter mode

Z[i] = AES-ENC(K, N \|\| uint32(i))

where AES-ENC is the AES encrypt function and uint32(i) is the little endian uint32 encoding of the integer i.

## AEAD Instances

We define six AEADs, in the format of {{RFC5116}}, that use AES-GCM-SST. They differ only in the key length (K_LEN) and the and tag length.

| Numeric ID | Name | K_LEN | tag_length |
| TBD1 | AEAD_AES_128_GCM_SST_4 | 16 | 4 |
| TBD2 | AEAD_AES_128_GCM_SST_8 | 16 | 8 |
| TBD3 | AEAD_AES_128_GCM_SST_10 | 16 | 10 |
| TBD4 | AEAD_AES_256_GCM_SST_4 | 32 | 4 |
| TBD5 | AEAD_AES_256_GCM_SST_8 | 32 | 8 |
| TBD6 | AEAD_AES_256_GCM_SST_10 | 32 | 10 |
{: #iana-algs title="AEAD Algorithms" cols="r l r r"}

Common parameters for the six AEADs:

* P_MAX (maximum size of the plaintext) is 2^36 - 47 octets.

* A_MAX (maximum size of the associated data) is 2^36 octets.

* N_MIN and N_MAX (minimum and maximum size of the nonce) are both 12 octets

* C_MAX (maximum size of the ciphertext and tag) is P_MAX + tag_length where tag_length can be between 4 and 16 bytes.

# Security Considerations

For the AEAD Algorithms in {{iana-algs}} the worst case forgery probability is bounded by ≈ 2^t where t is the tag length in bits. This is true for all allowed plaintext and associated data lengths.

No other than 96-bit

256 combined with short tags.

However, the field and the multiplication operation are taken from the POLYVAL function in the
 AES-SIV construction [x]. This has the advantage that it can be faster in software implementations and at the same time it can optionally reuse existing hardware implementations of GHASH from AES- GCM [3] (with some byte reversals and a simple multiplication).

Write why AES with 256 blocks would be good

  NOTE: There is a very small possibility that either or both of 𝐻 and 𝑄 are zero, since they are produced (pseudo-)randomly from the keystream generator. In such a case, the resulting tag will not depend on the message. There are no obvious ways to detect this condition for an attacker, and the specification admits this possibility in favour of complicating the flow with additional checks and regeneration of values.

  Updated P_LEN and A_LEN

  Write about 12 byte nonce only

  Security based on AES

tag_length can be between 4 and 16 bytes.

   tag length 4 16

# IANA Considerations

IANA is requested to assign the entries in the first two columns of {{iana-algs}} to the "AEAD Algorithms" registry under the "Authenticated Encryption with Associated Data (AEAD) Parameters" heading with this document as reference.

--- back

# Acknowledgments
{:numbered="false"}

The authors want to thank {{{Richard Barnes}}}, and {{{XXX}}} for their valuable comments and feedback.
