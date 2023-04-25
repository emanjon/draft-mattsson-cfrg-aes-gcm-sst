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

informative:


--- abstract

   This document defines the Galois Counter Mode with Secure Short Tags (GCM-SST) Authenticated Encryption with Associated Data
   (AEAD) algorithm. GCM-SST is defined with a general interface so that it can be used with any keystream generator. The main difference
   compared to GCM is that GCM-SST uses an additional secret point Q, which enables short tags forgery probability close to ideal. The document
   also registers several instansiations of GCM-SST useing AES-CTR as the keystream generator.

   This document is the product of the Crypto Forum Research Group.

--- middle

# Introduction

TODO Introduction

# GCM-SST with a Keystream Interface.

GCM-SST adheres to an AEAD interface and takes four bytestring parameters.

K, N, P, A

The keystream generator is instanziated with K and N. The keystream MUST NOT depend on P and A.
The minimum and maximum length of all parameters depends on the keystream generator.

The keystream generator produces a keystream of 128-bit quadwords Z.

GCM-SST internally uses three internal 16 bytes subkeys H, Q, M where

H = Z[0]
Q = Z[1]
M = Z[2]

First A and P are zero-padded to multiples of 128-bit quadwords and combined into a single message S.

S = zeropad(A) ｜｜ zeropad(P) ｜｜ len(A) ｜｜ len(C)

where len(A) and len(C) are the 64-bit representations of the bit lengths of A and C, respectively.

Then X is defined as:

X[0] = 0
X[i] = ( X[i-1] XOR S[i] ) * H

m is the number of 128-bit blocks in zeropad(A), n is the number of 128-bit blocks in zeropad(P)

Steps:

1. Let H = Z[0]
2. Let Q = Z[1]
3. Let M = Z[2]
4. Let ct = zeropad(P) XOR Z[3, n+3] 
5. Let S = zeropad(A) ｜｜ zeropad(P) ｜｜ len(A) ｜｜ len(P)
6. X = POLYVAL(H, S[0], s[1], ..., s[m+n-1])
7. T = POLYVAL(Q, X XOR s[m+n-1])
10. Let T = X2 XOR M
12. return ct ｜｜ trim(T, tag_length)




## Instansizating GCM-SSM with AES-CTR



## AEAD Instances

We define six AEADs, in the format of RFC 5116, that use AES-GCM-SST:
AEAD_AES_128_GCM_SST_4, AEAD_AES_128_GCM_SST_8, AEAD_AES_128_GCM_SST_10,
AEAD_AES_256_GCM_SST_4, AEAD_AES_256_GCM_SST_8, AEAD_AES_256_GCM_SST_10,
They differ only in the size of the AES key used and the tag length.

Common parameters for the six AEADs:

* P_MAX (maximum size of the plaintext) is 2^36 octets.

* A_MAX (maximum size of the associated data) is 2^36 octets.

* N_MIN = N_MAX = 12 octets.

* C_MAX = P_MAX + tag length.

For AEAD_AES_128_GCM_SST_4, AEAD_AES_128_GCM_SST_8, AEAD_AES_128_GCM_SST_10:

* K_LEN (key length) is 16 octets.

For AEAD_AES_256_GCM_SST_4, AEAD_AES_256_GCM_SST_8, AEAD_AES_256_GCM_SST_10:

* K_LEN (key length) is 32 octets.

For AEAD_AES_256_GCM_SST_4, AEAD_AES_256_GCM_SST_4:

* tag length is 4 octets.

For AEAD_AES_256_GCM_SST_8, AEAD_AES_256_GCM_SST_8:

* tag length is 8 octets.

For AEAD_AES_256_GCM_SST_10, AEAD_AES_256_GCM_SST_10:

* tag length is 10 octets.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

IANA is requested to assign the entries in Table X to the "AEAD Algorithms" registry
under the "Authenticated Encryption with Associated Data (AEAD) Parameters" heading
with this document as reference.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
