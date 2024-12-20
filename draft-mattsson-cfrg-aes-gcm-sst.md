---
title: "Galois Counter Mode with Strong Secure Tags (GCM-SST)"
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
- initials: M.
  surname: Campagna
  name: Matthew Campagna
  org: Amazon Web Services
  country: Canada
  email: campagna@amazon.com
- initials: A.
  surname: Maximov
  name: Alexander Maximov
  org: Ericsson
  abbrev: Ericsson
  country: Sweden
  email: alexander.maximov@ericsson.com
- initials: J.
  surname: Preuß Mattsson
  name: John Preuß Mattsson
  org: Ericsson
  abbrev: Ericsson
  country: Sweden
  email: john.mattsson@ericsson.com

normative:

  RFC5116:
  RFC8452:

  AES:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    title: "Advanced Encryption Standard (AES)"
    seriesinfo:
      "NIST": "Federal Information Processing Standards Publication 197"
    date: May 2023

  Rijndael:
    target: https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
    title: "AES Proposal: Rijndael"
    author:
      -
        ins: Joan Daemen
      -
        ins: Vincent Rijmen
    date: September 2003

informative:

  RFC3711:
  RFC4303:
  RFC6479:
  RFC7539:
  RFC8446:
  RFC8613:
  RFC9000:
  RFC9001:
  RFC9605:
  I-D.irtf-cfrg-aegis-aead:

  UIA2:
    target: https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/uea2uia2d1v21.pdf
    title: "UEA2 and UIA2 Specification"
    author:
      -
        ins: ETSI SAGE
    date: March 2009

  EIA3:
    target: https://www.gsma.com/solutions-and-impact/technologies/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf
    title: "128-EEA3 and 128-EIA3 Specification"
    author:
      -
        ins: ETSI SAGE
    date: January 2019

  BSI:
    target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html
    title: "Cryptographic Mechanisms Recommendations and Key Lengths"
    seriesinfo:
      "BSI": "Technical Guideline TR-02102-1"
    date: February 2024

  Multiple:
    target: https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/multi-forge-01.pdf
    title: "Multiple Forgery Attacks Against Message Authentication Codes"
    author:
      -
        ins: David McGrew
      -
        ins: Scott Fluhrer
    date: November 2024

  Reforgeability:
    target: https://eprint.iacr.org/2017/332.pdf
    title: "Reforgeability of Authenticated Encryption Schemes"
    author:
      -
        ins: Christian Forler
      -
        ins: Eik List
      -
        ins: Stefan Lucks
      -
        ins: akob Wenzel
    date: April 2017

  Inoue:
    target: https://eprint.iacr.org/2024/1928.pdf
    title: "Generic Security of GCM-SST"
    author:
      -
        ins: Akiko Inoue
      -
        ins: Ashwin Jha
      -
        ins: Bart Mennink
      -
        ins: Kazuhiko Minematsu
    date: November 2024

  Iwata:
    target: https://eprint.iacr.org/2012/438.pdf
    title: "Breaking and Repairing GCM Security Proofs"
    author:
      -
        ins: Tetsu Iwata
      -
        ins: Keisuke Ohashi
      -
        ins: Kazuhiko Minematsu
    date: August 2012

  Bernstein:
    target: https://cr.yp.to/antiforgery/permutations-20050323.pdf
    title: "Stronger Security Bounds for Permutations"
    author:
      -
        ins: Daniel J. Bernstein
    date: March 2005

  Procter:
    target: https://eprint.iacr.org/2014/613.pdf
    title: "A Security Analysis of the Composition of ChaCha20 and Poly1305"
    author:
      -
        ins: Gordon Procter
    date: August 2014

  SAGE23:
    target: https://www.3gpp.org/ftp/TSG_SA/WG3_Security/TSGS3_110_Athens/docs/S3-230642.zip
    title: "Specification of the 256-bit air interface algorithms"
    author:
      -
        ins: ETSI SAGE
    date: February 2023

  SAGE24:
    target: https://www.3gpp.org/ftp/tsg_sa/WG3_Security/TSGS3_117_Maastricht/docs/S3-243394.zip
    title: "Version 2.0 of 256-bit Confidentiality and Integrity Algorithms for the Air Interface"
    author:
      -
        ins: ETSI SAGE
    date: August 2024

  WID23:
    target: https://www.3gpp.org/ftp/tsg_sa/WG3_Security/TSGS3_113_Chicago/Docs/S3-235072.zip
    title: "New WID on Milenage-256 algorithm"
    author:
      -
        ins: 3GPP
    date: November 2023

  WID24:
    target: https://www.3gpp.org/ftp/tsg_sa/TSG_SA/TSGS_103_Maastricht_2024-03/Docs/SP-240476.zip
    title: "New WID on Addition of 256-bit security Algorithms"
    author:
      -
        ins: 3GPP
    date: March 2024

  ZUC:
    target: https://eprint.iacr.org/2021/1439
    title: "An Addendum to the ZUC-256 Stream Cipher"
    author:
      -
        ins: ZUC Design Team
    date: September 2024

  Options:
    target: https://csrc.nist.gov/csrc/media/Presentations/2024/options-for-encryption-algorithms-and-modes/images-media/sess-3-regenscheid-acm-workshop-2024.pdf
    title: "NIST Options in for Encryption Algorithms and Modes of Operation"
    author:
      -
        ins: NIST
    date: June 2024

  Comments38B:
    target: https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38b-initial-public-comments-2024.pdf
    title: "Public Comments on SP 800-38B"
    author:
      -
        ins: NIST
    date: September 2024

  Sec5G:
    target: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3169
    title: "Security architecture and procedures for 5G System"
    author:
      -
        ins: 3GPP TS 33.501
    date: September 2024

  PDCP:
    target: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3196
    title: "NR; Packet Data Convergence Protocol (PDCP) specification"
    author:
      -
        ins: 3GPP TS 38.323
    date: September 2024

  Collision:
    target: https://eprint.iacr.org/2021/236
    title: "Collision Attacks on Galois/Counter Mode (GCM)"
    author:
      -
        ins: J. Preuß Mattsson
    date: September 2024

  Lindell:
    target: https://mailarchive.ietf.org/arch/browse/cfrg/?gbt=1&index=cWpv0QgX2ltkWhtd3R9pEW7E1CA
    title: "Comment on AES-GCM-SST"
    author:
      -
        ins: Y. Lindell
    date: May 2024

  Degabriele:
    target: https://csrc.nist.gov/csrc/media/Presentations/2024/universal-hash-designs-for-an-accordion-mode/images-media/sess-7-degabriele-acm-workshop-2024.pdf
    title: "Universal Hash Designs for an Accordion Mode"
    author:
      -
        ins: J. Degabriele
      -
        ins: J. Gilcher
      -
        ins: J. Govinden
      -
        ins: K. Paterson
    date: June 2024

  SMAC:
    target: https://eprint.iacr.org/2024/819
    title: "A new stand-alone MAC construct called SMAC"
    author:
      -
        ins: D. Wang
      -
        ins: A. Maximov
      -
        ins: P. Ekdahl
      -
        ins: T. Johansson
    date: June 2024

  Robust:
    target: https://link.springer.com/article/10.1007/s00145-023-09489-9
    title: "Robust Channels: Handling Unreliable Networks in the Record Layers of QUIC and DTLS 1.3"
    author:
      -
        ins: M. Fischlin
      -
        ins: F. Günther
      -
        ins: C. Janson
    date: January 2024

  MoQ:
    target: https://datatracker.ietf.org/wg/moq/about/
    title: "Media Over QUIC"
    author:
      -
        ins: IETF
    date: September 2022

  Revise:
    target: https://csrc.nist.gov/news/2023/proposal-to-revise-sp-800-38d
    title: "Announcement of Proposal to Revise SP 800-38D"
    author:
      -
        ins: NIST
    date: August 2023

  SNOW:
    target: https://eprint.iacr.org/2021/236
    title: "SNOW-Vi: an extreme performance variant of SNOW-V for lower grade CPUs"
    author:
      -
        ins: P. Ekdahl
      -
        ins: T. Johansson
      -
        ins: A. Maximov
      -
        ins: J. Yang
    date: March 2021

  SST1:
    target: https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Galois%20Counter%20Mode%20with%20Secure%20Short%20Tags.pdf
    title: "Galois Counter Mode with Strong Secure Tags (GCM-SST)"
    author:
      -
        ins: M. Campagna
      -
        ins: A. Maximov
      -
        ins: J. Preuß Mattsson
    date: October 2023

  SST2:
    target: https://csrc.nist.gov/csrc/media/Presentations/2023/galois-counter-mode-with-secure-short-tags/images-media/sess-5-mattsson-bcm-workshop-2023.pdf
    title: "Galois Counter Mode with Strong Secure Tags (GCM-SST)"
    author:
      -
        ins: M. Campagna
      -
        ins: A. Maximov
      -
        ins: J. Preuß Mattsson
    date: October 2023

  GCM:
    target: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    seriesinfo:
      "NIST": "Special Publication 800-38D"
    author:
      -
        ins: M. Dworkin
    date: November 2007

  Ascon:
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.ipd.pdf
    title: "Ascon-Based Lightweight Cryptography Standards for Constrained Devices"
    seriesinfo:
      "NIST": "Special Publication 800-232 Initial Public Draft"
    author:
      -
        ins: Meltem Sönmez Turan
      -
        ins: Kerry A. McKay
      -
        ins: Donghoon Chang
      -
        ins: Jinkeon Kang
      -
        ins: John Kelsey
    date: November 2024

  GCM-Update:
    target: https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/gcm-update.pdf
    title: "GCM Update"
    author:
      -
        ins: D. McGrew
      -
        ins: J. Viega
    date: May 2005

  Gueron:
    target: https://csrc.nist.gov/csrc/media/Presentations/2023/constructions-based-on-the-aes-round/images-media/sess-5-gueron-bcm-workshop-2023.pdf
    title: "Constructions based on the AES Round and Polynomial Multiplication that are Efficient on Modern Processor Architectures"
    author:
      -
        ins: S. Gueron
    date: October 2023

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

  Rogaway:
    target: https://www.cryptrec.go.jp/exreport/cryptrec-ex-2012-2010r1.pdf
    title: "Evaluation of Some Blockcipher Modes of Operation"
    author:
      -
        ins: P. Rogaway
    date: February 2011

  Bellare:
    target: https://eprint.iacr.org/2016/564.pdf
    title: "The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3"
    author:
      -
        ins: M. Bellare
      -
        ins: B. Tackmann
    date: November 2017

--- abstract

This document defines the Galois Counter Mode with Strong Secure Tags (GCM-SST) Authenticated Encryption with Associated Data (AEAD) algorithm. GCM-SST can be used with any keystream generator, not just 128-bit block ciphers. The main differences from GCM are the use of an additional subkey Q, the derivation of fresh subkeys H and Q for each nonce, and the replacement of the GHASH function with the POLYVAL function from AES-GCM-SIV. This enables truncated tags with near-ideal forgery probabilities, even against multiple forgery attacks, which are significant security improvements over GCM. GCM-SST is designed for unicast security protocols with replay protection and addresses the strong industry demand for fast encryption with less overhead and high security. This document registers several instances of GCM-SST using Advanced Encryption Standard (AES) and Rijndael-256-256.

--- middle

# Introduction

Advanced Encryption Standard (AES) in Galois Counter Mode (AES-GCM) {{GCM}} is a widely used AEAD algorithm {{RFC5116}} due to its attractive performance in both software and hardware as well as its provable security. During the NIST standardization, Ferguson pointed out two weaknesses in the GCM authentication function {{Ferguson}}. The first weakness significantly increases the probability of successful forgery for long messages. The second weakness reveals the subkey H if an attacker succeeds in creating forgeries. Once H is known, the attacker can consistently forge subsequent messages, drastically increasing the probability of multiple successful forgeries. The two weaknesses are problematic for all tag lengths but are especially critical when short tags are used.

In a comment to NIST, Nyberg et al. {{Nyberg}} explained how small changes based on proven theoretical constructions mitigate these weaknesses. Unfortunately, NIST did not follow the advice from Nyberg et al. and instead specified additional requirements for use with short tags in Appendix C of {{GCM}}. NIST did not give any motivations for the parameter choices or the assumed security levels. Mattsson et al. {{Mattsson}} later demonstrated that attackers can almost always obtain feedback on the success or failure of forgery attempts, contradicting the assumptions NIST made for short tags. Furthermore, NIST appears to have relied on non-optimal attacks when calculating the parameters. Rogaway {{Rogaway}} criticizes the use of GCM with short tags and recommends prohibiting tags shorter than 96 bits. Reflecting the critique, NIST is planning to remove support for GCM with tags shorter than 96 bits {{Revise}}. NIST has not indicated any plans to address the absence of reforgeability resistance. When AES-GCM is used in QUIC {{RFC9001}}, the expected number of forgeries can be equivalent to that of an ideal MAC with a length of 64.4 bits.

Short tags are widely used, 32-bit tags are standard in most radio link layers including 5G {{Sec5G}}, 64-bit tags are very common in transport and application layers of the Internet of Things, and 32-, 64-, and 80-bit tags are common in media-encryption applications. Audio packets are small, numerous, and ephemeral. As such, they are highly sensitive to cryptographic overhead, but as each packet typically encodes only 20 ms of audio, forgery of individual packets is not a big concern and barely noticeable. Due to its weaknesses, GCM is typically not used with short tags. The result is either decreased performance from larger than needed tags {{MoQ}}, or decreased performance from using much slower constructions such as AES-CTR combined with HMAC {{RFC3711}}{{RFC9605}}. Short tags are also useful to protect packets whose payloads are secured at higher layers, protocols where the security is given by the sum of the tag lengths, and in constrained radio networks, where the low bandwidth preclude many repeated trial. For all applications of short tags it is essential that the MAC behaves like an ideal MAC, i.e., the forgery probability is ≈ 2<sup>-tag_length</sup> even after many generated MACs, many forgery attempts, and after a successful forgery. Users and implementors of cryptography expect algorithms to behave like ideal MACs. For a comprehensive discussion on the use cases and requirements of short tags, see {{Comments38B}}.

This document defines the Galois Counter Mode with Strong Secure Tags (GCM-SST) Authenticated Encryption with Associated Data (AEAD) algorithm following the recommendations from Nyberg et al. {{Nyberg}}. GCM-SST is defined with a general interface, allowing it to be used with any keystream generator, not just 128-bit block ciphers. The main differences from GCM {{GCM}} are the introduction of an additional subkey Q, the derivation of fresh subkeys H and Q for each nonce, and the replacement of the GHASH function with the POLYVAL function from AES-GCM-SIV {{RFC8452}}, see {{GCM-SST}}. These changes enable truncated tags with near-ideal forgery probabilities, even against multiple forgery attacks, see {{Security}}. GCM-SST is designed for use in unicast security protocols with replay protection such as TLS {{RFC8446}}, QUIC {{RFC9000}}, SRTP {{RFC3711}}, and PDCP {{PDCP}}, where its authentication tag behaves like an ideal MAC. Compared to Poly1305 {{RFC7539}} and GCM {{RFC5116}}, GCM-SST can provide better integrity with less overhead. Its performance is similar to GCM {{GCM}}, with the two additional AES invocations compensated by the use of POLYVAL, the ”little-endian version” of GHASH, which is faster on little-endian architectures. GCM-SST retains the additive encryption characteristic of GCM, which enables efficient implementations on modern processor architectures, see {{Gueron}} and Section 2.4 of {{GCM-Update}}.

This document also registers several GCM-SST instances using Advanced Encryption Standard (AES) {{AES}} and Rijndael with 256-bit keys and blocks (Rijndael-256-256) {{Rijndael}} in counter mode as keystream generators and with tag lengths of 32, 64, 96, and 112 bits, see {{AES-GCM-SST}}. The authentication tags in all registered GCM-SST instances behave like ideal MACs, which is not the case at all for GCM {{GCM}}. 3GPP has standardized the use of Rijndael-256-256 for authentication and key generation in 3GPP TS 35.234–35.237 {{WID23}}. NIST is anticipated to standardize Rijndael-256-256 {{Options}}, although there might be revisions to the key schedule.

GCM-SST was originally developed by ETSI SAGE, under the name Mac5G, following a request from 3GPP, with several years of discussion and refinement contributing to its design {{SAGE23}}{{SAGE24}}.  Mac5G is constructed similarly to the integrity algorithms used for SNOW 3G {{UIA2}} and ZUC {{EIA3}}. 3GPP has decided to standardize GCM-SST for use with AES-256 {{AES}}, SNOW 5G {{SNOW}}, and ZUC-256 {{ZUC}} in 3GPP TS 35.240–35.248 {{WID24}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following notation is used in the document:

* K is the key as defined in {{RFC5116}}
* N is the nonce as defined in {{RFC5116}}
* A is the associated data as defined in {{RFC5116}}
* P is the plaintext as defined in {{RFC5116}}
* Z is the keystream
* ct is the ciphertext
* tag is the authentication tag
* = is the assignment operator
* != is the inequality operator
* x \|\| y is concatenation of the octet strings x and y
* ⊕ is the bitwise exclusive or operator XOR
* len(x) is the length of x in bits.
* zeropad(x) right pads an octet string x with zeroes to a multiple of 128 bits
* truncate(x, t) is the truncation operation.  The first t bits of x are kept
* n is the number of 128-bit chunks in zeropad(P)
* m is the number of 128-bit chunks in zeropad(A)
* POLYVAL is defined in {{RFC8452}}
* BE32(x) is the big-endian encoding of 32-bit integer x
* LE64(x) is the little-endian encoding of 64-bit integer x
* V[y] is the 128-bit chunk with index y in the array V; the first chunk has index 0.
* V[x:y] are the range of chunks x to y in the array V

# Galois Counter Mode with Strong Secure Tags (GCM-SST) {#GCM-SST}

This section defines the Galois Counter Mode with Strong Secure Tags (GCM-SST) AEAD algorithm following the recommendations from Nyberg et al. {{Nyberg}}. GCM-SST is defined with a general interface so that it can be used with any keystream generator, not just a 128-bit block cipher.

GCM-SST adheres to an AEAD interface {{RFC5116}} and the encryption function takes four variable-length octet string parameters. A secret key K, a nonce N, the associated data A, and a plaintext P. The keystream generator is instantiated with K and N. The keystream MAY depend on P and A. The minimum and maximum lengths of all parameters depend on the keystream generator. The keystream generator produces a keystream Z consisting of 128-bit chunks where the first three chunks Z[0], Z[1], and Z[2] are used as the three subkeys H, Q, and M. The following keystream chunks Z[3], Z[4], ..., Z[n + 2] are used to encrypt the plaintext. Instead of GHASH {{GCM}}, GCM-SST makes use of the POLYVAL function from AES-GCM-SIV {{RFC8452}}, which results in more efficient software implementations on little-endian architectures. GHASH and POLYVAL can be defined in terms of one another {{RFC8452}}. The subkeys H and Q are field elements used in POLYVAL while the subkey M is used for the final masking of the tag. Both encryption and decryption are only defined on inputs that are a whole number of octets. Figures illustrating the GCM-SST encryption and decryption functions can be found in {{SST1}}, {{SST2}}, and {{Inoue}}.

For every computational procedure that is specified in this document, a conforming implementation MAY replace the given set of steps with any mathematically equivalent set of steps. In other words, different procedures that produce the correct output for every input are permitted.

## Authenticated Encryption Function

The encryption function Encrypt(K, N, A, P) encrypts a plaintext and returns the ciphertext along with an authentication tag that verifies the authenticity of the plaintext and associated data, if provided.

Prerequisites and security:

* The key MUST be randomly chosen from a uniform distribution.

* For a given key, a nonce MUST NOT be reused under any circumstances.

* Each key MUST be restricted to a single tag_length.

* Definitions of supported input-output lengths.

Inputs:

* Key K (variable-length octet string)
* Nonce N (variable-length octet string)
* Associated data A (variable-length octet string)
* Plaintext P (variable-length octet string)

Outputs:

* Ciphertext ct (variable-length octet string)
* Tag tag (octet string with length tag_length)

Steps:

1. If the lengths of K, N, A, P are not supported return error and abort
2. Initiate keystream generator with K and N
3. Let H = Z[0], Q = Z[1], M = Z[2]
4. Let ct = P ⊕ truncate(Z[3:n + 2], len(P))
5. Let S = zeropad(A) \|\| zeropad(ct)
6. Let L = LE64(len(ct)) \|\| LE64(len(A))
7. Let X = POLYVAL(H, S[0], S[1], ...)
8. Let full_tag = POLYVAL(Q, X ⊕ L) ⊕ M
9. Let tag = truncate(full_tag, tag_length)
10. Return (ct, tag)

## Authenticated Decryption Function

The decryption function Decrypt(K, N, A, ct, tag) decrypts a ciphertext, verifies that the authentication tag is correct, and returns the plaintext on success or an error if the tag verification failed.

Prerequisites and security:

* The calculation of the plaintext P (step 10) MAY be done in parallel with the tag verification (step 3-9). If the tag verification fails, the plaintext P and the expected_tag MUST NOT be given as output.

* Each key MUST be restricted to a single tag_length.

* Definitions of supported input-output lengths.

Inputs:

* Key K (variable-length octet string)
* Nonce N (variable-length octet string)
* Associated data A (variable-length octet string)
* Ciphertext ct (variable-length octet string)
* Tag tag (octet string with length tag_length)

Outputs:

* Plaintext P (variable-length octet string) or an error indicating that the authentication tag is invalid for the given inputs.

Steps:

1. If the lengths of K, N, A, or ct are not supported, or if len(tag) != tag_length return error and abort
2. Initiate keystream generator with K and N
3. Let H = Z[0], Q = Z[1], M = Z[2]
4. Let S = zeropad(A) \|\| zeropad(ct)
5. Let L = LE64(len(ct)) \|\| LE64(len(A))
6. Let X = POLYVAL(H, S[0], S[1], ...)
7. Let full_tag = POLYVAL(Q, X ⊕ L) ⊕ M
8. Let expected_tag = truncate(full_tag, tag_length)
9. If tag != expected_tag, return error and abort
10. Let P = ct ⊕ truncate(Z[3:n + 2], len(ct))
11. If N passes replay protrection, return P

The comparison of tag and expected_tag in step 9 MUST be performed in constant time to prevent any information leakage about the position of the first mismatched byte. For a given key, a plaintext MUST NOT be returned unless it is certain that a plaintext has not been returned for the same nonce. Replay protection can be performed either before step 1 or during step 11.

## Encoding (ct, tag) Tuples

Applications MAY keep the ciphertext and the authentication tag in distinct structures or encode both as a single octet string C. In the latter case, the tag MUST immediately follow the ciphertext ct:

C = ct \|\| tag

# AES and Rijndael-256-256 in GCM-SST {#AES-GCM-SST}

This section defines Advanced Encryption Standard (AES) and Rijndael with 256-bit keys and blocks (Rijndael-256-256) {{Rijndael}} in Galois Counter Mode with Strong Secure Tags.

## AES-GCM-SST

When GCM-SSM is instantiated with AES (AES-GCM-SST), the keystream generator is AES in counter mode

Z[i] = ENC(K, N \|\| BE32(i))

where ENC is the AES Cipher function {{AES}}. Big-endian counters align with existing implementations of counter mode.

## Rijndael-GCM-SST

When GCM-SST is instantiated with Rijndael-256-256 (Rijndael-GCM-SST), the keystream generator is Rijndael-256-256 in counter mode

Z[2i]   = ENC(K, N \|\| BE32(i))[0]

Z[2i+1] = ENC(K, N \|\| BE32(i))[1]

where ENC is the Rijndael-256-256 Cipher function {{Rijndael}}.

## AEAD Instances and Constraints {#instances}

We define twelve AEAD instances, in the format of {{RFC5116}}, that use AES-GCM-SST and Rijndael-GCM-SST with tag lengths of 32, 64, 96, and 112 bits. The key length and tag length are related to different security properties, and an application encrypting audio packets with small tags might require 256-bit confidentiality.

| Name | K_LEN (bytes) | P_MAX = A_MAX (bytes) | tag_length (bits) |
| AEAD_AES_128_GCM_SST_4 | 16 | 2<sup>36</sup> - 48 | 32 |
| AEAD_AES_128_GCM_SST_8 | 16 | 2<sup>36</sup> - 48 | 64 |
| AEAD_AES_128_GCM_SST_12 | 16 | 2<sup>35</sup> | 96 |
| AEAD_AES_128_GCM_SST_14 | 16 | 2<sup>19</sup> | 112 |
| AEAD_AES_256_GCM_SST_4 | 32 | 2<sup>36</sup> - 48 | 32 |
| AEAD_AES_256_GCM_SST_8 | 32 | 2<sup>36</sup> - 48 | 64 |
| AEAD_AES_256_GCM_SST_12 | 32 | 2<sup>35</sup> | 96 |
| AEAD_AES_256_GCM_SST_14 | 32 | 2<sup>19</sup> | 112 |
| AEAD_RIJNDAEL_GCM_SST_4 | 32 | 2<sup>36</sup> - 48 | 32 |
| AEAD_RIJNDAEL_GCM_SST_8 | 32 | 2<sup>36</sup> - 48 | 64 |
| AEAD_RIJNDAEL_GCM_SST_12 | 32 | 2<sup>35</sup> | 96 |
| AEAD_RIJNDAEL_GCM_SST_14 | 32 | 2<sup>19</sup> | 112 |
{: #iana-algs title="AEAD Algorithms" cols="l r r r"}

Common parameters for the six AEAD instances:

* N_MIN = N_MAX (minimum and maximum size of the nonce) is 12 octets for AES, while for Rijndael-256-256, it is 28 bytes.

* C_MAX (maximum size of the ciphertext and tag) is P_MAX + tag_length (in bytes)

* Q_MAX (maximum number of invocations of the encryption function) is 2<sup>32</sup> for AES-GCM-SST, while for Rijndael-GCM-SST, it is 2<sup>88</sup>.

* V_MAX (maximum number of invocations of the decryption function) is 2<sup>48</sup> for AES-GCM-SST, while for Rijndael-GCM-SST, it is 2<sup>88</sup>.

The maximum size of the plaintext (P_MAX) and the maximum size of the associated data (A_MAX) have been lowered from GCM {{RFC5116}}. To enable forgery probability close to ideal, even with maximum size plaintexts and associated data, we set P_MAX = A_MAX = min(2<sup>131 - tag_length</sup>, 2<sup>36</sup> - 48). Security protocols employing GCM-SST MAY impose stricter limits on P_MAX and A_MAX. Just like {{RFC5116}}, AES-GCM-SST and Rijndael-GCM-SST only allow a fixed nonce length (N_MIN = N_MAX) of 96-bit and 224-bits respectively. For the AEAD algorithms in {{iana-algs}} the worst-case forgery probability is bounded by ≈ 2<sup>-tag_length</sup> {{Nyberg}}. This is true for all allowed plaintext and associated data lengths.

The V_MAX constraint ensures that the Bernstein bound factor is δ ≈ 1 for AES-GCM-SST in protocols where ℓ ≈ 2<sup>12</sup>, such as QUIC {{RFC9000}}, and always δ ≈ 1 for Rijndael-GCM-SST. In addtion to restricting the Bernstein bound factor, the Q_MAX constraint also keeps the attack complexity of distinguishing attacks at an acceptable level. Since encryption and decryption queries play an equivalent role in the Bernstein bound, it follows that Q_MAX ≤ V_MAX. Security protocols employing GCM-SST MAY impose stricter limits on Q_MAX and V_MAX. Refer to {{Security}} for further details.

# Security Considerations {#Security}

GCM-SST introduces an additional subkey Q, alongside the subkey H. The inclusion of Q enables truncated tags with forgery probabilities close to ideal. Both H and Q are derived for each nonce, which significantly decreases the probability of multiple successful forgeries. These changes are based on proven theoretical constructions and follows the recommendations in {{Nyberg}}. Inoue et al. {{Inoue}} prove that GCM-SST is a provably secure authenticated encryption mode, with security guaranteed for evaluations under fresh nonces, even if some earlier nonces have been reused.

GCM-SST is designed for use in unicast security protocols with replay protection. Every key MUST be randomly chosen from a uniform distribution. GCM-SST MUST be used in a nonce-respecting setting: for a given key, a nonce MUST only be used once in the encryption function and only once in a successful decryption function call. The nonce MAY be public or predictable. It can be a counter, the output of a permutation, or a generator with a long period. GCM-SST MUST NOT be used with random nonces [Collision] and MUST be used with replay protection. Reuse of nonces in successful encryption and decryption function calls enable universal forgery {{Lindell}}{{Inoue}}. For a given tag length, GCM-SST has stricly better security properties than GCM. GCM allows universal forgery with lower complexity than GCM-SST, even when nonces are not reused. Implementations SHOULD add randomness to the nonce by XORing a unique number like a sequence number with a per-key random secret salt of the same length as the nonce. This significantly improves security against precomputation attacks and multi-key attacks [Bellare] and is for example implemented in TLS 1.3 {{RFC8446}}, OSCORE {{RFC8613}}, and {{Ascon}}. By increasing the nonce length from 96 bits to 224 bits, Rijndael-256-256-GCM-SST can offer significantly greater security against precomputation and multi-key attacks compared to AES-256-GCM-SST. GCM-SST SHOULD NOT be used in multicast or broadcast scenarios. While GCM-SST offers better security properties than GCM for a given tag length in such contexts, it does not behave like an ideal MAC.

## Integrity

The GCM-SST tag_length SHOULD NOT be smaller than 4 bytes and cannot be larger than 16 bytes. Let ℓ = (P_MAX + A_MAX) / 16 + 1. When tag_length < 128 - log2(ℓ) bits, the worst-case forgery probability is bounded by ≈ 2<sup>-tag_length</sup> {{Nyberg}}. The tags in the AEAD algorithms listed in {{instances}} therefore have an almost perfect security level. This is significantly better than GCM where the security level is only tag_length - log2(ℓ) bits {{GCM}}. For a graph of the forgery probability, refer to Fig. 3 in {{Inoue}}. As one can note, for 128-bit tags and long messages, the forgery probability is not close to ideal and similar to GCM {{GCM}}. If tag verification fails, the plaintext and expected_tag MUST NOT be given as output. In GCM-SST, the full_tag is independent of the specified tag length unless the application explicitly incorporates tag length into the keystream or the nonce.

The expected number of forgeries, when tag_length < 128 - log2(ℓ) bits, depends on the keystream generator. For an ideal keystream generator, the expected number of forgeries is ≈ v / 2<sup>tag_length</sup>, where v is the number of decryption queries, which is ideal. For AES-GCM-SST, the expected number of forgeries is ≈ δ<sub>128</sub> ⋅ v / 2<sup>tag_length</sup>, where the Bernstein bound factor δ<sub>b</sub> ⪅ 1 + (q + v)<sup>2</sup> ⋅ ℓ<sup>2</sup> / 2<sup>b+1</sup>, which is near-ideal. This far outperforms AES-GCM, where the expected number of forgeries is ≈ δ<sub>128</sub> ⋅ v<sup>2</sup> ⋅ ℓ / 2<sup>tag_length+1</sup>. For Rijndael-GCM-SST, the expected number of forgeries is ≈ δ<sub>256</sub> ⋅ v / 2<sup>tag_length</sup> ≈ v / 2<sup>tag_length</sup>, which is ideal. For further details on the integrity advantages and expected number of forgeries for GCM and GCM-SST, see {{Iwata}}, {{Inoue}}, {{Bernstein}}, and {{Multiple}}. BSI states that an ideal MAC with a 96-bit tag length is considered acceptable for most applications {{BSI}}, a requirement that AES-GCM-SST with 96-bit tags satisfies when δ ≈ 1. Achieving a comparable level of security with GCM, CCM, or Poly1305 is nearly impossible.

## Confidentiality

The confidentiality offered by AES-GCM-SST against passive attackers is equal to AES-GCM {{GCM}} and given by the birthday bound. Regardless of key length, an attacker can mount a distinguishing attack with a complexity of approximately 2<sup>129</sup> / q, where q is the number of invocations of the AES encryption function. In contrast, the confidentiality offered by Rijndael-256-256-GCM-SST against passive attackers is significantly higher. The complexity of distinguishing attacks for Rijndael-256-256-GCM-SST is approximately 2<sup>257</sup> / q, where q is the number of invocations of the Rijndael-256-256 encryption function. While Rijndael-256-256 in counter mode can provide strong confidentiality for plaintexts much larger than 2<sup>36</sup> octets, GHASH and POLYVAL do not offer adequate integrity for long plaintexts. To ensure robust integrity for long plaintexts, an AEAD mode would need to replace POLYVAL with a MAC that has better security properties, such as a Carter-Wegman MAC in a larger field {{Degabriele}} or other alternatives such as {{SMAC}}.

The confidentiality offered by AES-GCM-SST against active attackers is directly linked to the forgery probability. Depending on the protocol and application, forgeries can significantly compromise privacy, in addition to affecting integrity and authenticity. It MUST be assumed that attackers always receive feedback on the success or failure of their forgery attempts. Therefore, attacks on integrity, authenticity, and confidentiality MUST all be carefully evaluated when selecting an appropriate tag length.

## Weak keys

In general, there is a very small possibility in GCM-SST that either or both of the subkeys H and Q are zero, so called weak keys. If H is zero, the authentication tag depends only on the length of P and A and not on their content. If Q is zero, the authentication tag does not depend on P and A. Due to the masking with M, there are no obvious ways to detect this condition for an attacker, and the specification admits this possibility in favor of complicating the flow with additional checks and regeneration of values. In AES-GCM-SST, H and Q are generated with a permutation on different input, so H and Q cannot both be zero.

## Replay Protection

The details of the replay protection mechanism is determined by the security protocol utilizing GCM-SST. If the nonce includes a sequence number, it can be used for replay protection. Alternatively, a separate sequence number can be used, provided there is a one-to-one mapping between sequence numbers and nonces. The choice of a replay protection mechanism depends on factors such as the expected degree of packet reordering, as well as protocol and implementation details. For examples of replay protection mechanisms, see {{RFC4303}} and {{RFC6479}}. Implementing replay protection by requiring ciphertexts to arrive in order and terminating the connection if a single decryption fails is NOT RECOMMENDED as this approach reduces robustness and availability while exposing the system to denial-of-service attacks {{Robust}}.

## Comparision with ChaCha20-Poly1305 and AES-GCM

{{comp1}} compares the integrity of AES-GCM-SST, ChaCha20-Poly1305 {{RFC7539}}, and AES-GCM {{RFC5116}} in unicast security protocols with replay protection, where v represents the number of decryption queries. In Poly1305 and GCM, the forgery probability depends on ℓ = (P_MAX + A_MAX) / 16 + 1. In AES-based algorithms, the Bernstein bound introduces a factor δ ⪅ 1 + (q + v)<sup>2</sup> ⋅ ℓ<sup>2</sup> / 2<sup>129</sup>. Notably, GCM does not provide any reforgeability resistance, which significantly increases the expected number of forgeries.
Refer to {{Procter}}, {{Iwata}}, and {{Multiple}} for further details.

| Name | Forgery probability before first forgery | Forgery probability after first forgery| Expected number of forgeries |
| GCM_SST_14 | 1 / 2<sup>112</sup> | 1 / 2<sup>112</sup> | δ ⋅ v / 2<sup>112</sup> |
| GCM_SST_12 | 1 / 2<sup>96</sup> | 1 / 2<sup>96</sup> | δ ⋅ v / 2<sup>96</sup> |
| POLY1305 | ℓ / 2<sup>103</sup> | ℓ / 2<sup>103</sup> | v ⋅ ℓ / 2<sup>103</sup> |
| GCM | ℓ / 2<sup>128</sup> | 1 | δ&nbsp;⋅&nbsp;v<sup>2</sup>&nbsp;⋅&nbsp;ℓ&nbsp;/&nbsp;2<sup>129</sup> |
{: #comp1 title="Comparision between AES-GCM-SST, ChaCha20-Poly1305, and AES-GCM in unicast security protocols with replay protection. v is the number of decryption queries, ℓ is the maximum length of plaintext and associated data, measured in 128-bit chunks, and δ is the Bernstein bound factor." cols="l r r r"}

{{comp2}} compares the integrity of AES-GCM-SST, ChaCha20-Poly1305 {{RFC7539}}, and AES-GCM {{RFC5116}} in unicast QUIC {{RFC9000}}{{RFC9001}}, a security protocol with mandatory replay protection, and where the combined size of plaintext and associated data is less than ≈ 2<sup>16</sup> bytes (ℓ ≈ 2<sup>12</sup>). GCM_SST_14 and GCM_SST_12 provide better integrity than ChaCha20-Poly1305 {{RFC7539}} and AES-GCM {{RFC5116}}, while also reducing overhead by 2–4 bytes. For AES-GCM-SST and ChaCha20-Poly1305, the expected number of forgeries is linear in v when replay protection is employed. ChaCha20-Poly1305 achieves a security level equivalent to that of an ideal MAC with a length of 91 bits. For AES-GCM, replay protection does not mitigate reforgeries, the expected number of forgeries grows quadratically with v, and GCM provides significantly worse integrity than AES-GCM-SST and ChaCha20-Poly1305 unless v is kept very small. With v = 2<sup>52</sup> as allowed for AES-GCM in QUIC {{RFC9001}}, the expected number of forgeries for AES-GCM is equivalent to that of an ideal MAC with a length of 64.4 bits.

| Name | Overhead (bytes) | Forgery probability before first forgery | Forgery probability after first forgery| Expected number of forgeries |
| GCM_SST_14 | 14 | 1 / 2<sup>112</sup> | 1 / 2<sup>112</sup> | v / 2<sup>112</sup> |
| GCM_SST_12 | 12 |1 / 2<sup>96</sup> | 1 / 2<sup>96</sup> | v / 2<sup>96</sup> |
| POLY1305 | 16 |1 / 2<sup>91</sup> | 1 / 2<sup>91</sup> | v / 2<sup>91</sup> |
| GCM | 16 | 1 / 2<sup>116</sup> | 1 | δ&nbsp;⋅&nbsp;v<sup>2</sup>&nbsp;/&nbsp;2<sup>117</sup> |
{: #comp2 title="Comparision between AES-GCM-SST, ChaCha20-Poly1305, and AES-GCM in unicast QUIC, where the maximum packet size is 65536 bytes." cols="l r r r r"}

# IANA Considerations

IANA is requested to assign the entries in the first column of {{iana-algs}} to the "AEAD Algorithms" registry under the "Authenticated Encryption with Associated Data (AEAD) Parameters" heading with this document as reference.

--- back

# AES-GCM-SST Test Vectors

## AES-GCM-SST Test #1 (128-bit key)

~~~~~~~~~~~~~~~~~~~~~~~
       KEY = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
     NONCE = { 30 31 32 33 34 35 36 37 38 39 3a 3b }
         H = { 22 ce 92 da cb 50 77 4b ab 0d 18 29 3d 6e ae 7f }
         Q = { 03 13 63 96 74 be fa 86 4d fa fb 80 36 b7 a0 3c }
         M = { 9b 1d 49 ea 42 b0 0a ec b0 bc eb 8d d0 ef c2 b9 }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #1a
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { }
 PLAINTEXT = { }
encode-LEN = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  full-TAG = { 9b 1d 49 ea 42 b0 0a ec b0 bc eb 8d d0 ef c2 b9 }
       TAG = { 9b 1d 49 ea }
CIPHERTEXT = { }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #1b
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 }
 PLAINTEXT = { }
encode-LEN = { 00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 }
  full-TAG = { 7f f3 cb a4 d5 f3 08 a5 70 4e 2f d5 f2 3a e8 f9 }
       TAG = { 7f f3 cb a4 }
CIPHERTEXT = { }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #1c
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b }
encode-LEN = { 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  full-TAG = { f8 de 17 85 fd 1a 90 d9 81 8f cb 7b 44 69 8a 8b }
       TAG = { f8 de 17 85 }
CIPHERTEXT = { 64 f0 5b ae 1e d2 40 3a 71 25 5e dd }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #1d
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
               70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e }
encode-LEN = { f8 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 }
  full-TAG = { 93 43 56 14 0b 84 48 2c d0 14 c7 40 7e e9 cc b6 }
       TAG = { 93 43 56 14 }
CIPHERTEXT = { 64 f0 5b ae 1e d2 40 3a 71 25 5e dd 53 49 5c e1
               7d c0 cb c7 85 a7 a9 20 db 42 28 ff 63 32 10 }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #1e
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
               70 }
encode-LEN = { 88 00 00 00 00 00 00 00 78 00 00 00 00 00 00 00 }
  full-TAG = { f8 50 b7 97 11 43 ab e9 31 5a d7 eb 3b 0a 16 81 }
       TAG = { f8 50 b7 97 }
CIPHERTEXT = { 64 f0 5b ae 1e d2 40 3a 71 25 5e dd 53 49 5c e1
               7d }
~~~~~~~~~~~~~~~~~~~~~~~

## AES-GCM-SST Test #2 (128-bit key)

~~~~~~~~~~~~~~~~~~~~~~~
       KEY = { 29 23 be 84 e1 6c d6 ae 52 90 49 f1 f1 bb e9 eb }
     NONCE = { 9a 50 ee 40 78 36 fd 12 49 32 f6 9e }
       AAD = { 1f 03 5a 7d 09 38 25 1f 5d d4 cb fc 96 f5 45 3b
               13 0d }
 PLAINTEXT = { ad 4f 14 f2 44 40 66 d0 6b c4 30 b7 32 3b a1 22
               f6 22 91 9d }
         H = { 2d 6d 7f 1c 52 a7 a0 6b f2 bc bd 23 75 47 03 88 }
         Q = { 3b fd 00 96 25 84 2a 86 65 71 a4 66 e5 62 05 92 }
         M = { 9e 6c 98 3e e0 6c 1a ab c8 99 b7 8d 57 32 0a f5 }
encode-LEN = { a0 00 00 00 00 00 00 00 90 00 00 00 00 00 00 00 }
  full-TAG = { 45 03 bf b0 96 82 39 b3 67 e9 70 c3 83 c5 10 6f }
       TAG = { 45 03 bf b0 96 82 39 b3 }
CIPHERTEXT = { b8 65 d5 16 07 83 11 73 21 f5 6c b0 75 45 16 b3
               da 9d b8 09 }
~~~~~~~~~~~~~~~~~~~~~~~

## AES-GCM-SST Test #3 (256-bit key)

~~~~~~~~~~~~~~~~~~~~~~~
       KEY = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
               10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f }
     NONCE = { 30 31 32 33 34 35 36 37 38 39 3a 3b }
         H = { 3b d9 9f 8d 38 f0 2e a1 80 96 a4 b0 b1 d9 3b 1b }
         Q = { af 7f 54 00 16 aa b8 bc 91 56 d9 d1 83 59 cc e5 }
         M = { b3 35 31 c0 e9 6f 4a 03 2a 33 8e ec 12 99 3e 68 }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #3a
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { }
 PLAINTEXT = { }
encode-LEN = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  full-TAG = { b3 35 31 c0 e9 6f 4a 03 2a 33 8e ec 12 99 3e 68 }
       TAG = { b3 35 31 c0 e9 6f 4a 03 }
CIPHERTEXT = { }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #3b
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 }
 PLAINTEXT = { }
encode-LEN = { 00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 }
  full-TAG = { 63 ac ca 4d 20 9f b3 90 28 ff c3 17 04 01 67 61 }
       TAG = { 63 ac ca 4d 20 9f b3 90 }
CIPHERTEXT = { }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #3c
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b }
encode-LEN = { 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  full-TAG = { e1 de bf fd 5f 3a 85 e3 48 bd 6f cc 6e 62 10 90 }
       TAG = { e1 de bf fd 5f 3a 85 e3 }
CIPHERTEXT = { fc 46 2d 34 a7 5b 22 62 4f d7 3b 27 }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #3d
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
               70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e }
encode-LEN = { f8 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 }
  full-TAG = { c3 5e d7 83 9f 21 f7 bb a5 a8 a2 8e 1f 49 ed 04 }
       TAG = { c3 5e d7 83 9f 21 f7 bb }
CIPHERTEXT = { fc 46 2d 34 a7 5b 22 62 4f d7 3b 27 84 de 10 51
               33 11 7e 17 58 b5 ed d0 d6 5d 68 32 06 bb ad }
~~~~~~~~~~~~~~~~~~~~~~~

### Case #3e
{:numbered="false"}

~~~~~~~~~~~~~~~~~~~~~~~
       AAD = { 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e }
 PLAINTEXT = { 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
               70 }
encode-LEN = { 88 00 00 00 00 00 00 00 78 00 00 00 00 00 00 00 }
  full-TAG = { 49 7c 14 77 67 a5 3d 57 64 ce fd 03 26 fe e7 b5 }
       TAG = { 49 7c 14 77 67 a5 3d 57 }
CIPHERTEXT = { fc 46 2d 34 a7 5b 22 62 4f d7 3b 27 84 de 10 51
               33 }
~~~~~~~~~~~~~~~~~~~~~~~

## AES-GCM-SST Test #4 (256-bit key)

~~~~~~~~~~~~~~~~~~~~~~~
       KEY = { 29 23 be 84 e1 6c d6 ae 52 90 49 f1 f1 bb e9 eb
               b3 a6 db 3c 87 0c 3e 99 24 5e 0d 1c 06 b7 b3 12 }
     NONCE = { 9a 50 ee 40 78 36 fd 12 49 32 f6 9e }
       AAD = { 1f 03 5a 7d 09 38 25 1f 5d d4 cb fc 96 f5 45 3b
               13 0d }
 PLAINTEXT = { ad 4f 14 f2 44 40 66 d0 6b c4 30 b7 32 3b a1 22
               f6 22 91 9d }
         H = { 13 53 4b f7 8a 91 38 fd f5 41 65 7f c2 39 55 23 }
         Q = { 32 69 75 a3 3a ff ae ac af a8 fb d1 bd 62 66 95 }
         M = { 59 48 44 80 b6 cd 59 06 69 27 5e 7d 81 4a d1 74 }
encode-LEN = { a0 00 00 00 00 00 00 00 90 00 00 00 00 00 00 00 }
  full-TAG = { c4 a1 ca 9a 38 c6 73 af bf 9c 73 49 bf 3c d5 4d }
       TAG = { c4 a1 ca 9a 38 c6 73 af bf 9c }
CIPHERTEXT = { b5 c2 a4 07 f3 3e 99 88 de c1 2f 10 64 7b 3d 4f
               eb 8f f7 cc }
~~~~~~~~~~~~~~~~~~~~~~~

# Change Log
{:removeInRFC="true" numbered="false"}

Changes from -12 to -13:

* Changed name to Strong Secure Tags to better illustrate that GCM-SST is intended to improve security for all tag lengths.
* Editorial changes

Changes from -11 to -12:

* Introduced Q_MAX and V_MAX as formal names for the invocation constraints.
* Described that masking is important to mitigate weak keys.
* Improved and expanded the section comparing GCM-SST with Poly1305 and GCM.
* Editorial changes including subsections in the security considerations.

Changes from -10 to -11:

* Added that protocols can impose stricter limits on P_MAX and A_MAX
* Added constraints on the number of decryption queries v
* More info on replay protection implementation
* More info on nonce constructions
* Introduced the Bernstein bound factor δ instead of just assuming that δ < 2
* Clarified differences between GCM-SST with different keystream generators (ideal, AES, Rijndael)
* Made it clearer that Table 1 is for unicast security protocols with replay protection and that Poly1305 is keyed with ChaCha20.
* Editorial changes including RFC 2119 terminology

Changes from -09 to -10:

* Corrected some probabilites that were off by a factor 2
* Editorial changes.

Changes from -07 to -09:

* Changed replay requirements to allow replay protection after decryption to align with protocols like QUIC and DTLS 1.3.
* Added a comparision between GCM_SST_14, GCM_SST_12, GCM_16, POLY1305 in protocols like QUIC
* Added text on the importance of behaving like an ideal MAC
* Consideration on replay protection mechanisms
* Added text and alternative implementations borrowed from NIST
* Added constrainst of 2^32 encryption invocations aligning with NIST
* Added text explainting that GCM-SST offer strictly better security than GCM and that "GCM allows universal forgery with lower complexity than GCM-SST, even when nonces are not reused", to avoid any misconceptions that Lindell's attack makes GCM-SST weaker than GCM in any way.

Changes from -06 to -07:

* Replaced 80-bit tags with 96- and 112-bit tags.
* Changed P_MAX and A_MAX and made them tag_length dependent to enable 96- and 112-bit tags with near-ideal security.
* Clarified that GCM-SST tags have near-ideal forgery probabilities, even against multiple forgery attacks, which is not the case at all for GCM.
* Added formulas for expeted number of forgeries for GCM-SST (q ⋅ 2<sup>-tag_length</sup>) and GCM (q<sup>2</sup> ⋅ (n + m + 1) ⋅ 2<sup>-tag_length + 1</sup>) and stated that GCM-SST fulfils BSI recommendation of using 96-bit ideal MACs.

Changes from -04 to -06:

* Reference to Inoue et al. for security proof, forgery probability graph, and improved attack when GCM-SST is used without replay protection.
* Editorial changes.

Changes from -03 to -04:

* Added that GCM-SST is designed for unicast protocol with replay protection
* Update info on use cases for short tags
* Updated info on ETSI and 3GPP standardization of GCM-SST
* Added Rijndael-256-256
* Added that replay is required and that random nonces, multicast, and broadcast are forbidden based on attack from Yehuda Lindell
* Security considerations for active attacks on privacy as suggested by Thomas Bellebaum
* Improved text on H and Q being zero.
* Editorial changes.

Changes from -02 to -03:

* Added performance information and considerations.
* Editorial changes.

Changes from -01 to -02:

* The length encoding chunk is now called L
* Use of the notation POLYVAL(H, X_1, X_2, ...) from RFC 8452
* Removed duplicated text in security considerations.

Changes from -00 to -01:

* Link to NIST decision to remove support for GCM with tags shorter than 96-bits based on Mattsson et al.
* Mention that 3GPP 5G Advance will use GCM-SST with AES-256 and SNOW 5G.
* Corrected reference to step numbers during decryption
* Changed T to full_tag to align with tag and expected_tag
* Link to images from the NIST encryption workshop illustrating the GCM-SST encryption and decryption functions.
* Updated definitions
* Editorial changes.

# Acknowledgments
{:numbered="false"}

The authors thank {{{Richard Barnes}}}, {{{Thomas Bellebaum}}}, {{{Scott Fluhrer}}}, {{{Eric Lagergren}}}, {{{Yehuda Lindell}}}, {{{Kazuhiko Minematsu}}}, and {{{Erik Thormarker}}} for their valuable comments and feedback. Some of the formatting and text were inspired by and borrowed from {{I-D.irtf-cfrg-aegis-aead}}.
