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

  RFC8452:

informative:

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

   This document defines the Galois Counter Mode with Secure Short Tags (GCM-SST) Authenticated Encryption with Associated Data
   (AEAD) algorithm. GCM-SST is defined with a general interface so that it can be used with any keystream generator. The main difference
   compared to GCM is that GCM-SST uses an additional secret point Q, which enables short tags forgery probability close to ideal. The document
   also registers several instansiations of GCM-SST useing AES-CTR as the keystream generator.

   This document is the product of the Crypto Forum Research Group.

--- middle

# Introduction

   This document defines the Galois Counter Mode with Secure Short Tags (GCM-SST) Authenticated Encryption with Associated Data
   (AEAD) algorithm. GCM-SST is defined with a general interface so that it can be used with any keystream generator. The main difference
   compared to GCM is that GCM-SST uses an additional secret point Q, which enables short tags forgery probability close to ideal. The document
   also registers several instansiations of GCM-SST useing AES-CTR as the keystream generator.

AES in Galois Counter Mode (AES-GCM) is a very widely used algorithm due to its good performance in both software and hardware as well as it's provable security. During the NIST standardization, Fergoson pointed out two weaknesses in the GCM authentication function. The weaknesses are especially concerning when GCM is used with short tags. The first weakness significantly increases the probability of successful forgery. The second weakness reveals the authentication key H if the attacker manages to create successful forgeries. With knowledge of the authentication key H, the attacker always succeeds with subsequent forgeries. The probability of successful multiple forgeries is therefore significantly increased.

As a response to the weaknesses Ferguson found, Nyberg et. al. explained how small changes based on proven theoretical constuctions mitigates Ferguson weaknesses. Unfortunatly NIST did not follow the advice from Nyberg et. al. and instead specified Appendic D. The calcualtions and security levels behind the Appendix was not disclosed. As shown by Mattsson et al., NISTs assumption that an attacker do get knowledge about tag failure is not realistic and NIST appeared to have used a non-optimal attack to calculate the limits. Due to the remaining weaknesses, GCM is not often used with short tags. The result is decreased performance from larger than needed tags, or decreased performance from using other constructions such as AES-CTR with HMAC-SHA-256.

In this document we specify Galois Counter Mode with Secure Short Tags (GCM-SST). GCM-SST is very similar to GCM but incoperated the two suggestions from Nyberg et. al. namely to use a second authentication key Q for the last step and do derive the authentication keys from the nonce N. As proven by Nyberg et. al. this creates a Polynomial MAC with forgery probability close to ideal. In addition to the two changes suggested by Nyberg et all. GCM-SST also make the two following changes compared to GCM
- Instead of GHASH, the faster POLYVAL function is used.
- The specification is made general so that any keystream generator can be used. Not just a 128-bit block cipher.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# GCM-SST with a Keystream Interface.

GCM-SST adheres to an AEAD interface and takes four bytestring parameters.

K, N, P, A

The keystream generator is instanziated with K and N. The keystream MUST NOT depend on P and A.
The minimum and maximum length of all parameters depends on the keystream generator.

The keystream generator produces a keystream of 128-bit quadwords Z.

GCM-SST internally uses three internal 16 bytes subkeys H, Q, M where

H = Z/[0]/
Q = Z/[1]/
M = Z/[2]/

First A and P are zero-padded to multiples of 128-bit quadwords and combined into a single message S.

S = zeropad(A) ｜｜ zeropad(P) ｜｜ len(A) ｜｜ len(C)

where len(A) and len(C) are the 64-bit representations of the bit lengths of A and C, respectively.

Then X is defined as:

X[0] = 0
X[i] = ( X[i-1] XOR S[i] ) * H

m is the number of 128-bit blocks in zeropad(A), n is the number of 128-bit blocks in zeropad(P)

Steps:

1. Let H = Z[0], Q = Z[1], M = Z[2]
2. Let ct = zeropad(P) XOR Z[3, n+3]
3. Let S = zeropad(A) ｜｜ ct ｜｜ len(A) ｜｜ len(P)
4. X = POLYVAL(H, S[0], s[1], ..., s[m + n - 1])
5. T = POLYVAL(Q, X XOR s[m + n]) XOR M
6. return (trim(ct, len(P)), rim(T, tag_length))


## Instansizating GCM-SSM with AES

When GCM-SSM is instanciated with AES, then

Z[i] = AES-ENC(K, N || i)

where AES is the AES encrypt function with key K and IV = N || i and where i is the 32-bit representation.

## AEAD Instances

We define six AEADs, in the format of RFC 5116, that use AES-GCM-SST:
They differ only in the size of the AES key used and the tag length.

｜ Numeric ID ｜ Name ｜ K_LEN ｜ tag_length ｜
｜ TDB1 ｜ AEAD_AES_128_GCM_SST_4 ｜ 16 ｜ 4 ｜
｜ TDB1 ｜ AEAD_AES_128_GCM_SST_8 ｜ 16 ｜ 8 ｜
｜ TDB1 ｜ AEAD_AES_128_GCM_SST_10 ｜ 16 ｜ 10 ｜
｜ TDB1 ｜ AEAD_AES_256_GCM_SST_4 ｜ 32 ｜ 4 ｜
｜ TDB1 ｜ AEAD_AES_256_GCM_SST_8 ｜ 32 ｜ 8 ｜
｜ TDB1 ｜ AEAD_AES_256_GCM_SST_10 ｜ 32 ｜ 10 ｜

Common parameters for the six AEADs:

* P_MAX (maximum size of the plaintext) is 2^36 octets.

* A_MAX (maximum size of the associated data) is 2^36 octets.

* N_MIN = N_MAX = 12 octets.

* C_MAX = P_MAX + tag_length.

* K_LEN (key length) is 16 or 32 octets.

* tag length is 4, 8, or 10 octets.

# Security Considerations

TODO Security

# IANA Considerations

IANA is requested to assign the entries in Table X (first two columns) to the "AEAD Algorithms" registry
under the "Authenticated Encryption with Associated Data (AEAD) Parameters" heading
with this document as reference.

--- back

# Acknowledgments
{:numbered="false"}

The authors want to thank {{{Richard Barnes}}}, and {{{XXX}}} for their valuable comments and feedback.
