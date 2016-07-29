%%%

   Title = "SMTP MTA Strict Transport Security"
   abbrev = "MTA-STS"
   category = "std"
   docName = "draft-ietf-uta-mta-sts-01"
   ipr = "trust200902"
   area = "Applications"
   workgroup = "Using TLS in Applications"
   keyword = [""]

   date = 2016-07-08T00:00:00Z

   [[author]]
   initials="D."
   surname="Margolis"
   fullname="Daniel Margolis"
   organization="Google, Inc"
     [author.address]
     email="dmargolis (at) google.com"
   [[author]]
   initials="M."
   surname="Risher"
   fullname="Mark Risher"
   organization="Google, Inc"
     [author.address]
     email="risher (at) google (dot com)"
   [[author]]
   initials="B."
   surname="Ramakrishnan"
   fullname="Binu Ramakrishnan"
   organization="Yahoo!, Inc"
     [author.address]
     email="rbinu (at) yahoo-inc (dot com)"
   [[author]]
   initials="A."
   surname="Brotman"
   fullname="Alexander Brotman"
   organization="Comcast, Inc"
     [author.address]
     email="alexander_brotman (at) cable.comcast (dot com)"
   [[author]]
   initials="J."
   surname="Jones"
   fullname="Janet Jones"
   organization="Microsoft, Inc"
     [author.address]
     email="janet.jones (at) microsoft (dot com)"

%%%

.# Abstract

SMTP MTA-STS is a mechanism enabling mail service providers to declare their
ability to receive TLS-secured connections, to declare particular methods for
certificate validation, and to request that sending SMTP servers report upon
and/or refuse to deliver messages that cannot be delivered securely.

{mainmatter}

# Introduction

The STARTTLS extension to SMTP [@!RFC3207] allows SMTP clients and hosts to
establish secure SMTP sessions over TLS. In its current form, however, it fails
to provide (a) message confidentiality — because opportunistic STARTTLS is
subject to downgrade attacks — and (b) server authenticity — because the trust
relationship from email domain to MTA server identity is not cryptographically
validated.

While such _opportunistic_ encryption protocols provide a high barrier against
passive man-in-the-middle traffic interception, any attacker who can delete
parts of the SMTP session (such as the "250 STARTTLS" response) or who can
redirect the entire SMTP session (perhaps by overwriting the resolved MX record
of the delivery domain) can perform such a downgrade or interception attack.

This document defines a mechanism for recipient domains to publish policies
specifying:

   * whether MTAs sending mail to this domain can expect TLS support
   * how MTAs can validate the TLS server certificate presented during mail
     delivery
   * the expected identity of MXs that handle mail for this domain
   * what an implementing sender should do with messages when TLS cannot be
     successfully negotiated

The mechanism described is separated into four logical components:

   1. policy semantics: whether senders can expect a server for the
      recipient domain to support TLS encryption and how to validate the TLS
      certificate presented
   2. policy discovery & authentication: how to discover a domain's published
      STS policy and determine the authenticity of that policy
   3. failure report format: a mechanism for informing recipient domains about
      aggregate failure statistics
   4. failure handling: what sending MTAs should do in the case of policy
      failures

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when
they appear in this document, are to be interpreted as described in [@!RFC2119].

We also define the following terms for further use in this document:

* STS Policy: A definition of the expected TLS availability and behavior, as
  well as the desired actions for a given domain when a sending MTA encounters
  different results.
* Policy Domain: The domain against which an STS Policy is defined.
* Policy Authentication: Authentication of the STS policy retrieved for a recipient
  domain by the sender.

# Related Technologies

The DANE TLSA record [@!RFC7672] is similar, in that DANE is also designed to
upgrade opportunistic encryption into required encryption. DANE requires DNSSEC
[@!RFC4033] for the secure delivery of policies; the mechanism described here
presents a variant for systems not yet supporting DNSSEC.

## Differences from DANE

The primary difference between the mechanism described here and DANE is that
DANE requires the use of DNSSEC to authenticate DANE TLSA records, whereas SMTP
STS relies on the certificate authority (CA) system to avoid interception. (For
a thorough discussion of this trade-off, see the section _Security_
_Considerations_.)

In addition, SMTP MTA-STS introduces a mechanism for failure reporting and a
report-only mode, enabling offline ("report-only") deployments and auditing for
compliance.

### Advantages of SMTP MTA-STS when compared to DANE

SMTP MTA-STS offers the following advantages compared to DANE:

   * Infrastructure: In comparison to DANE, this proposal does not require
     DNSSEC be deployed on either the sending or receiving domain. In addition,
     the reporting feature of SMTP MTA-STS can be deployed to perform offline
     analysis of STARTTLS failures, enabling mail providers to gain insight into
     the security of their SMTP connections without the need to modify MTA
     codebases directly.
   * Offline or report-only usage: DANE does not provide a reporting
     mechanism and does not have a concept of "report-only" for failures; as a
     result, a service provider cannot receive metrics on TLS acceptability
     without asking senders to enforce a given policy; similarly, senders who
     cannot enforce DANE constraints at send-time have no mechanism to provide
     recipients such metrics from an offline (and potentially easier-to-deploy)
     logs-analysis batch process.

### Advantages of DANE when compared to SMTP MTA-STS

* Infrastructure: DANE may be easier for some providers to deploy. In
  particular, for providers who already support DNSSEC, SMTP MTA-STS would
  additionally require they host a HTTPS webserver and obtain a CA-signed
  X.509 certificate for the recipient domain.

* Security: DANE offers an advantage against policy-lookup DoS attacks; that is,
  while a DNSSEC-signed NXDOMAIN response to a DANE lookup authoritatively
  indicates the lack of a DANE record, such an option to authenticate policy
  non-existence does not exist when looking up a policy over plain DNS.

# Policy Semantics

SMTP MTA-STS policies are distributed via a "well known" HTTPS endpoint in the
Policy Domain. A corresponding TXT record in the DNS alerts sending MTAs to
the presence of a policy file.

(Future implementations may move to alternate methods of policy discovery or
distribution. See the section _Future_ _Work_ for more discussion.)

**The MTA-STS TXT record MUST specify the following fields:**

* `v`: (plain-text, required). Currently only "STSv1" is supported.
* `id`: (plain-text, required). A short string used to track policy updates.
  This string MUST uniquely identify a given instance of a policy, such that 
  senders can determine when the policy has been updated by comparing to the `id`
  of a previously seen policy, and must also match the `policy_id` value of the
  distributed policy.

A lenient parser SHOULD accept a policy file implementing a superset of this
specification, in which case unknown values SHALL be ignored.

**Policies MUST specify the following fields in JSON** [@!RFC4627] **format:**

* `version`: (plain-text, required). Currently only "STSv1" is supported.
* `mode`: (plain-text, required). If "enforce", the receiving MTA requests that
  messages be delivered only if they conform to the STS policy. If "report" the
  receiving MTA requests that failure reports be delivered, as specified
  by the `rua` parameter.
* `mx`: MX patterns (list of plain-text MX match patterns, required). One or
  more comma-separated patterns matching the expected MX for this domain. For
  example, `["*.example.com", "*.example.net"]` indicates that mail for this
  domain might be handled by any MX whose hostname is a subdomain of
  "example.com" or "example.net". The semantics for these patterns should be the
  ones found in the "Checking of Wildcard Certificates" rules in Section 6.4.3
  of [@!RFC6125]. 
* `max_age`: Max lifetime of the policy (plain-text integer seconds). Well-behaved
  clients SHOULD cache a policy for up to this value from last policy fetch
  time.
* `policy_id`: A short string used to track policy updates. This string MUST
  uniquely identify a given instance of a policy, such that senders can
  determine when the policy has been updated by comparing to the `policy_id` of
  a previously seen policy.

A lenient parser SHOULD accept a policy file which is valid JSON implementing a
superset of this specification, in which case unknown values SHALL be ignored.

## Formal Definition

### TXT Record

The formal definition of the `_mta_sts` TXT record, defined using [@!RFC5234],
is as follows:

    sts-text-record = sts-version *WSP %x3B *WSP sts-id

    sts-version     = "v" *WSP "=" *WSP %x53 %x54        ; "STSv1" 
                      %x53 %x76 %x31

    sts-id          = "id" *WSP "=" *WSP 1*32(ALPHA / DIGIT) 


### SMTP MTA-STS Policy

The formal definition of the SMTP MTA-STS policy, using [@!RFC5234], is as
follows:

    sts-record      = WSP %x7B WSP  ; { left curly bracket
                      sts-element   ; comma-separated
                      [             ; list
                      WSP %x2c WSP  ; of
                      sts-element   ; sts-elements
                      ]
                      WSP %x7d WSP  ; } right curly bracket

    sts-element     = sts-version / sts-mode / sts-id / sts-mx / sts-max_age

    sts-version     = %x22 "version" %x22 *WSP %x3a *WSP ; "version":
                      %x22 %x53 %x54 %x53 %x76 %x31      ; "STSv1"

    sts-mode        = %x22 "mode" %x22 *WSP %x3a *WSP    ; "mode":
                      %x22 ("report" / "enforce") %x22   ; "report"/"enforce"

    sts-id          = %x22 "policy_id" %x22 *WSP %x3a *WSP ; "policy_id":
                      %x22 1*32(ALPHA / DIGIT) %x22        ; some chars

    sts-mx          = %x22 "mx" $x22 *WSP %x3a *WSP      ; "mx":
                      %x5B                               ; [
                      domain-match                       ; comma-separated list
                      [WSP %x2c domain-match WSP]        ; of domain-matches
                      %x5B                               ; ]

    sts-max_age     = %x22 "max_age" %x22 *WSP $x3a *WSP ; "max_age":
                      1*10DIGIT                          ; some digits

    domain-match    = %x22 1*(dtext / "*") *("."         ; wildcard or label
                      1*dtext) %x22                      ; with 0+ more labels

    dtext           = ALPHA / DIGIT / %2D                ; A-Z, a-z, 0-9, "-" 

A size limitation in a sts-uri, if provided, is interpreted as a
count of units followed by an OPTIONAL unit size ("k" for kilobytes,
"m" for megabytes, "g" for gigabytes, "t" for terabytes).  Without a
unit, the number is presumed to be a basic byte count.  Note that the
units are considered to be powers of two; a kilobyte is 2^10, a
megabyte is 2^20, etc.

## Policy Discovery & Authentication

Senders discover a recipient domain's STS policy, by making an attempt to fetch
TXT records from the recipient domain's DNS zone with the name "_mta_sts". A
valid TXT record presence in "_mta_sts.example.com" indicates that the recipent
domain supports STS.  To allow recipient domains to safely serve new policies,
it is important that senders are able to authenticate a new policy retrieved for
a recipient domain.

Web PKI is the mechanism used for policy authentication. In this mechanism, the
sender fetches a HTTPS resource (policy) from a host at `policy.mta-sts` in the
Policy Domain. The policy is served from a "well known" URI:
`https://policy.mta-sts.example.com/.well-known/mta-sts/current.json`. To consider 
the policy as valid, the `policy_id` field in the policy MUST match the `id` 
field in the DNS TXT record under `_mta_sts`.

When fetching a new policy or updating a policy, the new policy MUST be
fully authenticated (HTTPS certificate validation + peer verification) before
use.  A policy which has not ever been successfully authenticated MUST NOT be
used to reject mail.

## Policy Expirations

In order to resist attackers inserting a fraudulent policy, SMTP MTA-STS
policies are designed to be long-lived, with an expiry typically greater than
two weeks.  Policy validity is controlled by two separate expiration times: the
lifetime indicated in the policy ("max_age=") and the TTL on the DNS record
itself. The policy expiration will ordinarily be longer than that of the DNS
TTL, and senders SHOULD cache a policy (and apply it to all mail to the
recipient domain) until the policy expiration.

An important consideration for domains publishing a policy is that senders will
see a policy expiration as relative to the fetch of a policy cached by their
recursive resolver. Consequently, a sender MAY treat a policy as valid for up to
{expiration time} + {DNS TTL}. Publishers SHOULD thus continue to expect senders
to apply old policies for up to this duration.

### Policy Updates

Updating the policy requires that the owner make changes in two places: the
`_mta_sts` RR record in the Policy Domain's DNS zone and at the corresponding
HTTPS endpoint. In the case where the HTTPS endpoint has been updated but the
TXT record has not been, senders will not know there is a new policy released
and may thus continue to use old, previously cached versions. Recipients should
thus expect a policy will continue to be used by senders until both the HTTPS
and TXT endpoints are updated and the TXT record's TTL has passed.

### Policy Rolling

Since the policy is served from "current" location. As a consequence, this
results in mismatch between `id` from DNS (possibly cached) and `policy_id` in
the policy file when updated. To avoid sync issues between two places, the
recipient domain may also serve the STS policy with the name $(id).json, and 
the `id` is the one from DNS STS TXT record. In such cases `current` would
act as a symlink to the latest version file. If the sender finds a mismatch
with `id` from DNS and the `policy_id` in the `current` policy file, it tries
to fetch the policy from $(id).json file. Once the `current` moves to a new
version, the old policy version will be kept for a short period of time 
(max_age + DNS TTL) and safely remove after that period.

## Policy Validation

When sending to an MX at a domain for which the sender has a valid and
non-expired SMTP MTA-STS policy, a sending MTA honoring SMTP MTA-STS MUST
validate that the recipient MX supports STARTTLS, and offers a valid PKIX based
TLS certificate. The certificate presented by the receiving MX MUST be valid
for the MX name and chain to a root CA that is trusted by the sending MTA. The
certificate MUST have a CN or SAN matching the MX hostname (as described in
[@!RFC6125]) and be non-expired.

## Policy Application

When sending to an MX at a domain for which the sender has a valid non-expired
SMTP MTA-STS policy, a sending MTA honoring SMTP MTA-STS MAY apply the result
of a policy validation one of two ways:

* `report`: In this mode, sending MTAs merely send a report to the designated
  report address indicating policy application failures. This can be done
  "offline", i.e. based on the MTA logs, and is thus a suitable low-risk option
  for MTAs who wish to enhance transparency of TLS tampering without making
  complicated changes to production mail-handling infrastructure.

* `enforce`: In this mode, sending MTAs SHOULD treat STS policy failures, in
  which the policy action is "reject", as a mail delivery error, and SHOULD
  terminate the SMTP connection, not delivering any more mail to the recipient
  MTA.

In `enforce` mode, however, sending MTAs MUST first check for a new
authenticated policy before actually treating a message failure as fatal.

Thus the control flow for a sending MTA that does online policy application
consists of the following steps:

1. Check for cached non-expired policy. If none exists, fetch the latest,
   authenticate and cache it.
2. Validate recipient MTA against policy. If valid, deliver mail.
3. If not valid and the policy specifies reporting, generate report.
4. If not valid and policy specifies rejection, perform the following
   steps:

  * Check for a new (non-cached) authenticated policy.
  * If one exists and the new policy is different, update the current policy and
    go to step 2.
  * If one exists and the new policy is same as the cached policy, treat the
    delivery as a failure.
  * If none exists and cached policy is not expired, treat the delivery as a
    failure.

Understanding the details of step 4 is critical to understanding the behavior of
the system as a whole.

Remember that each policy has an expiration time (which SHOULD be long, on the
order of days or months) and a validation method. With these two mechanisms and
the procedure specified in step 4, recipients who publish a policy have, in
effect, a means of updating a cached policy at arbitrary intervals, without the
risks (of a man-in-the-middle attack) they would incur if they were to shorten
the policy expiration time.

# Failure Reporting

Aggregate statistics on policy failures MAY be reported using the `TLSRPT`
reporting specification (TODO: Add Ref).


# IANA Considerations

There are no IANA considerations at this time.

# Security Considerations

SMTP Strict Transport Security protects against an active attacker who wishes to
intercept or tamper with mail between hosts who support STARTTLS. There are two
classes of attacks considered:

* Foiling TLS negotiation, for example by deleting the "250 STARTTLS" response
  from a server or altering TLS session negotiation. This would result in the
  SMTP session occurring over plaintext, despite both parties supporting TLS.

* Impersonating the destination mail server, whereby the sender might deliver
  the message to an impostor, who could then monitor and/or modify messages
  despite opportunistic TLS. This impersonation could be accomplished by
  spoofing the DNS MX record for the recipient domain, or by redirecting client
  connections intended for the legitimate recipient server (for example, by
  altering BGP routing tables).

SMTP Strict Transport Security relies on certificate validation via PKIX based TLS
identity checking [@!RFC6125]. Attackers who are able to obtain a valid certificate
for the targeted recipient mail service (e.g. by compromising a certificate authority)
are thus out of scope of this threat model.

Since we use DNS TXT record for policy discovery, an attacker who is able to
block DNS responses can suppress the discovery of an STS Policy, making the
Policy Domain appear not to have an STS Policy. The caching model described in
_Policy_ _Expirations_ is designed to resist this attack, and there is
discussion in the _Future_ _Work_ section around future distribution mechanisms
that are robust against this attack.

HTTP 302 redirects are not allowed while fetching policy from HTTPS endpoint.
Redirection is not desired because of the following reasons:
* By hosting policy on a sub-domain we allow the mail domain to outsource 
   their policy serving to a 3rd party; if needed. 
* We still need per-domain policy - hence there is not real benefit in doing so. 
   Or there should be an option for some kind of policy includes. 
* Additional complexity. following redirects may create security vulnerabilities

# Future Work

The authors would like to suggest multiple considerations for future discussion.

* Certificate pinning: One potential improvement in the robustness of the
  certificate validation methods discussed would be the deployment of public-key
  pinning as defined for HTTP in [@!RFC7469]. A policy extension supporting
  these semantics would enable Policy Domains to specify certificates that MUST
  appear in the MX certificate chain, thus providing resistence against
  compromised CA or DNSSEC zone keys.

* Policy distribution: As with Certificate Transparency ([@!RFC6962]), it may be
  possible to provide a verifiable log of policy *observations* (meaning which
  policies have been observed for a given Policy Domain). This would provide
  insight into policy spoofing or faked policy non-existence. This may be
  particularly useful for Policy Domains not using DNSSEC, since it would
  provide sending MTAs an authoritative source for whether a policy is expected
  for a given domain.

* Receive-from restrictions: Policy publishers may wish to also indicate to
  domains *receiving* mail from the Policy Domain that all such mail is expected
  to be sent via TLS. This may allow policy publishers to receive reports
  indicating sending MTA misconfigurations. However, the security properties of
  a "receiver-enforced" system differ from those of the current design; in
  particular, an active man-in-the-middle attacker may be able to exploit
  misconfigured sending MTAs in a way that would not be possible today with a
  sender-enforced model.

* Cipher and TLS version restrictions: Policy publishers may also wish to
  restrict TLS negotiation to specific ciphers or TLS versions.

# Contributors

Nicolas Lidzborski
Google, Inc
nlidz (at) google (dot com)

Wei Chuang
Google, Inc
weihaw (at) google (dot com)

Brandon Long
Google, Inc
blong (at) google (dot com)

Franck Martin
LinkedIn, Inc
fmartin (at) linkedin (dot com)

Klaus Umbach
1&1 Mail & Media Development & Technology GmbH
klaus.umbach (at) 1und1 (dot de)

Markus Laber
1&1 Mail & Media Development & Technology GmbH
markus.laber (at) 1und1 (dot de)


# Appendix 1: Validation Pseudocode
~~~~~~~~~
policy = policy_from_cache()
if not policy or is_expired(policy):
  policy = policy_from_https_endpoint()  // fetch and authenticate!
  update_cache = true
if policy:
  if invalid_mx_or_tls(policy):  // check MX and TLS cert
    if rua:
      generate_report()
    if p_reject():
      policy = policy_from_https_endpoint()  // fetch and authenticate #2!
      update_cache = true
      if invalid_mx_or_tls(policy):
        reject_message()
        update_cache = false
  if update_cache:
    cache(policy)
~~~~~~~~~

# Appendix 2: Domain Owner STS example record

## Example 1

The owner of example.com wishes to begin using STS with a policy that will
solicit aggregate feedback from receivers without affecting how the messages are
processed, in order to:

* Verify the identity of MXs that handle mail for this domain

* Confirm that its legitimate messages are sent over TLS

* Verify the validity of the certificates

* Determine how many messages would be affected by a strict policy

DNS STS policy indicator TXT record:
~~~~~~~~~
_mta_sts  IN TXT ( "v=STSv1; id=randomstr;" )
~~~~~~~~~

STS policy served from HTTPS endpoint of the policy (recipient) domain, and
is authenticated using Web PKI mechanism. The policy is fetched using HTTP
GET method.
~~~~~~~~~
{
  "version": "STSv1",
  "mode": "report",
  "policy_id": "randomstr",
  "mx": ["*.mail.example.com"],
  "max_age": 123456
}
~~~~~~~~~

The policy is authenticated using Web PKI mechanism.

# Appendix 3: DEEP Registration Elements

~~~~~~~~~
Name: mx-mismatch
Description: This indicates that the MX resolved for the recipient domain
             did not match the MX constraint specified in the policy.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: certificate-name-mismatch
Description: This indicates that the subject CNAME/SAN in the certificate
             presented by the receiving MX did not match the MX hostname
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: invalid-certificate
Description: This indicates that the certificate presented by the receiving MX
             did not validate according to the policy validation constraint.
             (Either it was not signed by a trusted CA or did not match the
             DANE TLSA record for the recipient MX.)
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: certificate-name-constraints-not-permitted
Description: The certificate request contains a name that is not listed as
             permitted in the name constraints extension of the cert issuer.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: certificate-name-constraints-excluded
Description: The certificate request contains a name that is listed as 
             excluded in the name constraints extension of the issuer.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: expired-certificate
Description: This indicates that the certificate has expired.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: starttls-not-supported
Description: This indicates that the recipient MX did not support STARTTLS.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: tlsa-invalid
Description: This indicates a validation error for Policy Domain specifying
             "tlsa" validation.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: dnssec-invalid
Description: This indicates a failure to validate DNS records for a Policy
             Domain specifying "tlsa" validation or "dnssec" authentication.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG

Name: sender-does-not-support-validation-method
Description: This indicates the sending system can never validate using the
             requested validation mechanism.
Intended Usage:  COMMON
Reference:  RFC XXXX (this document once published)
Submitter:  Authors of this document
Change Controller:  IESG
~~~~~~~~~

{backmatter}
