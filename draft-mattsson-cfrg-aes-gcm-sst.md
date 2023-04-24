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
