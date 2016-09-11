%%%

   Title = "SMTP MTA Strict Transport Security (MTA-STS)"
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
negotiate the use of a TLS channel for secure mail transmission.

While such _opportunistic_ encryption protocols provide a high barrier against
passive man-in-the-middle traffic interception, any attacker who can delete
parts of the SMTP session (such as the "250 STARTTLS" response) or who can
redirect the entire SMTP session (perhaps by overwriting the resolved MX record
of the delivery domain) can perform downgrade or interception attacks.

This document defines a mechanism for recipient domains to publish policies
specifying:

   * whether MTAs sending mail to this domain can expect TLS support
   * how to validate the names of the domain's MX hosts
   * what a conforming client should do with messages when TLS cannot be
     successfully negotiated

The mechanism described is separated into three logical components:

   1. policy semantics: whether senders can expect a server for the
      recipient domain to support TLS encryption
   2. policy discovery & authentication: how to discover a domain's published
      STS policy and determine the authenticity of that policy
   3. failure handling: what sending MTAs should do in the case of policy
      failures

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when
they appear in this document, are to be interpreted as described in [@!RFC2119].

We also define the following terms for further use in this document:

* STS Policy: A committment by the Policy Domain to support PKIX authenticated
  TLS for the specified MX hosts.
* Policy Domain: The domain for which an STS Policy is defined. (For
  example, when sending mail to "alice@example.com", the policy domain is
  "example.com".)
* Policy Authentication: Authentication of the STS policy retrieved for a recipient
  domain by the sender.

# Related Technologies

The DANE TLSA record [@!RFC7672] is similar, in that DANE is also designed to
upgrade opportunistic, unauthenticated encryption into required, authenticated
encryption. DANE requires DNSSEC [@!RFC4033] for authentication; the mechanism
described here instead relies on certificate authorities (CAs) and does not
require DNSSEC.

## Differences from DANE

The primary difference between the mechanism described here and DANE is that
DANE requires the use of DNSSEC to authenticate DANE TLSA records, whereas SMTP
MTA-STS relies on the certificate authority (CA) system to avoid interception.
(For a thorough discussion of this trade-off, see the section _Security_
_Considerations_.)

In addition, SMTP MTA-STS provides an optional report-only mode, enabling soft
deployments to detect policy failures.

# Policy Semantics

SMTP MTA-STS policies are distributed via a "well known" HTTPS endpoint in the
Policy Domain. A corresponding TXT record in the DNS signals to sending MTAs the
presence of a policy file. The character content of the TXT record is encoded as
US-ASCII.

**The MTA-STS TXT record MUST specify the following fields:**

* `v`: (plain-text, required). Currently only "STSv1" is supported.
* `id`: (plain-text, required). A short string used to track policy updates.
  This string MUST uniquely identify a given instance of a policy, such that 
  senders can determine when the policy has been updated by comparing to the `id`
  of a previously seen policy. There is no implied ordering of `id` fields
  between revisions.

**Policies MUST specify the following fields in JSON** [@!RFC4627] **format:**

* `version`: (plain-text, required). Currently only "STSv1" is supported.
* `mode`: (plain-text, required). If "enforce", the receiving MTA requests that
  messages be delivered only if they conform to the STS policy. If "report" the
  receiving MTA requests that failure reports be delivered, as specified
  by the `rua` parameter.
* `mx`: MX patterns (list of plain-text MX match patterns, required). One or
  more comma-separated patterns matching the expected MX for this domain. For
  example, `["*.example.com", "*.example.net"]` indicates that mail for this
  domain might be handled by any MX with a hostname at `example.com` or
  `example.net`, though _not_ hosts at subdomains. For example,
  `mx1.example.com` and `mx2.example.net` are both valid matches, but not
  `1234.dhcp.example.com`. The semantics for these patterns are those found in
  the "Checking of Wildcard Certificates" rules in Section 6.4.3 of [RFC6125].
* `max_age`: Max lifetime of the policy (plain-text positive integer seconds).
  Well-behaved clients SHOULD cache a policy for up to this value from last
  policy fetch time.

A lenient parser SHOULD accept TXT record sand policy files which are
syntactically valid (i.e. valid key-value pairs or valid JSON) implementing a
superset of this specification, in which case unknown values SHALL be ignored.

## Formal Definition

### TXT Record

An example TXT record is as below:

~~~~~~~~~
_mta_sts  IN TXT ( "v=STSv1; id=20160831085700Z;" )
~~~~~~~~~

The formal definition of the `_mta_sts` TXT record, defined using [@!RFC5234],
is as follows:

    sts-text-record = sts-version *WSP %x3B *WSP sts-id

    sts-version     = "v" *WSP "=" *WSP %x53 %x54        ; "STSv1" 
                      %x53 %x76 %x31

    sts-id          = "id" *WSP "=" *WSP 1*32(ALPHA / DIGIT) 


### SMTP MTA-STS Policy

An example policy is as below:

~~~~~~~~~
{
  "version": "STSv1",
  "mode": "enforce",
  "mx": ["*.mail.example.com"],
  "max_age": 123456
}
~~~~~~~~~


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


## Policy Expiration

In order to resist attackers inserting a fraudulent policy, SMTP MTA-STS
policies are designed to be long-lived, with an expiry typically greater than
two weeks.  Policy validity is controlled by the lifetime indicated in the
policy ("max_age="). Senders SHOULD cache a policy (and apply it to all mail to
the recipient domain) until the policy expiration.

To mitigate the risks of long-lived cached policies (which otherwise may make it
difficult for recipient domains to change infrastructure in ways which the
policy forbids), domains can, at any time, publish an updated policy. As
described in _Policy_ _Application_, senders MUST fetch a new policy before
treating a validation failure as a permanent delivery failure. 

### Policy Updates

Updating the policy requires that the owner make changes in two places: the
`_mta_sts` TXT record in the Policy Domain's DNS zone and at the corresponding
HTTPS endpoint. In the case where the HTTPS endpoint has been updated but the
TXT record has not been, senders will not know there is a new policy released
and may thus continue to use old, previously cached versions.  Recipients should
thus expect a policy will continue to be used by senders until both the HTTPS
and TXT endpoints are updated and the TXT record's TTL has passed.

### Policy Revocation

Senders MUST treat a policy with a max_age of 0 as a revocation: they should
purge any previously cached policy and proceed to deliver mail to the recipient
domain as though it never had an STS policy.

## Policy Discovery & Authentication

Senders discover a recipient domain's MTA-STS policy by fetching a TXT record
with the name generated by prefixing `_mta_sts` to the recipient domain. A valid
TXT record at `_mta_sts.example.com` indicates that the domain `example.com`
supports MTA-STS.

When sending to a recipient domain for which a valid TXT record exists, a
compliant sender will then fetch via the GET method an HTTPS resource containing
the policy body from a host at the `mta-sts` host of the policy domain, using an
[@!RFC5785] "well-known" path of `.well-known/mta-sts.json`.  For
`example.com`, this would be
`https://mta-sts.example.com/.well-known/mta-sts.json`.

### HTTPS Policy Fetching

When fetching a new policy or updating a policy, the HTTPS endpoint MUST present
a TLS certificate which is valid for the `mta-sts` host (as described in
[@!RFC6125]), chain to a root CA that is trusted by the sending CA, and be
non-expired. It is expected that sending MTAs use a set of trusted CAs similar
to those in widely deployed Web browsers and operating systems.

HTTP 3xx redirects MUST NOT be followed.

Senders may wish to rate-limit the frequency of attempts to fetch the HTTPS
endpoint even if a valid TXT record for the recipient domain exists. In the case
that the HTTPS GET fails, we suggest implementions may limit further attempts to
a period of five minutes or longer per version ID, to avoid overwhelming
resource-constrained recipients with cascading failures.

### Policy Selection for Smart Hosts

When sending mail via a "smart host"--an intermediate SMTP relay rather than the
message recipient's server--compliant senders MUST treat the smart host domain
as the policy domain for the purposes of policy discovery and application.

## Policy Validation

When sending to an MX at a domain for which the sender has a valid and
non-expired SMTP MTA-STS policy, a sending MTA honoring SMTP MTA-STS MUST
validate that the recipient MX matches the `mx` pattern from the recipient
domain's policy, supports STARTTLS, and offers a valid PKIX based TLS
certificate.

The certificate presented by the receiving MX MUST be valid for the MX name and
chain to a root CA that is trusted by the sending MTA. The certificate MUST have
a CN or SAN matching the MX hostname (as described in [@!RFC6125]) and be
non-expired.

In the case of an "implicit" MX record (as specified in [@!RFC2821]) where no MX
RR exists for the recipient domain but there is an A RR, the MX hostname is
assumed to be that of the A RR and should be validated as such.

This section does not dictate the behavior of sending MTAs when policies fail to
validate; in particular, validation failures of policies which specify "report
only" mode MUST NOT be interpreted as delivery failures, as described in the
section _Policy_ _Application_.

## Policy Application

When sending to an MX at a domain for which the sender has a valid, non-expired
STS policy, a sending MTA honoring SMTP MTA-STS applies the result of a policy
validation one of two ways, depending on the value of the policy `mode` field:

1. `report`: In this mode, sending MTAs merely send a report (as described in the
   `TLSRPT` specification (TODO: add ref)) indicating policy application
   failures. This can be used for "soft" deployments, to ensure a policy will not
   cause domain-wide mail delivery failures while being adopted or during
   infrastructure changes.

2. `enforce`: In this mode, sending MTAs treat STS policy failures as a mail
   delivery error, and MUST NOT deliver the message to this host. However, note
   that MTAs that honor `enforce` mode MUST first check for the existing of an
   updated, authenticated policy before *permanently* failing messages. This is
   to ensure that failures only occur if a sending MTA is in fact validating
   against the most recent version of the recipient domain's policy.

Note that despite the presence of an `enforce` policy, STS-aware sending MTAs
may in some cases choose to deliver mail to non-validating MXes due to external
reasons, such as an inability to enforce STS at send-time (i.e., some domains
may validate STS policies offline and only choose to report failures) or
concerns about the completeness of their own trusted CA list.

Finally, an STS Policy MUST NOT be be used to reject mail until it has been
successfully validated when delivering at least one message to the Policy
Domain. This is to limit the risk of misconfigurations when deploying new
policies.

### MX Preference in Enforce Mode

When applying a policy specifying `enforce` mode, sending MTAs SHOULD select
recipient MXs by first eliminating any MXs at lower priority than the current
host (if in the MX candidate set), then eliminating any non-matching (as
specified by the STS policy) MX hosts from the candidate MX set, and then
attempting delivery to matching hosts as indicated by their MX priority, until
delivery succeeds or the MX candidate set is empty.

If none of the attempted MX hosts validate according to the policy, the policy
MUST be refreshed at least once, as described in _Policy_ _Discovery_ _&_
_Authentication_, before a message should be permanently rejected.

### Policy Application Control Flow

The control flow for a sending MTA consists of the following steps:

1. Check for a cached, non-expired policy. If none exists and the `_mta_sts` TXT
   record is present for the recipient domain, fetch a new policy, authenticate,
   and cache it.
2. Validate candidate MX or MXs against policy. If a valid MX is discovered,
   deliver mail and mark cached policy as "successfully applied."
3. If no valid recipient MX is found, the cached policy mode is `reject`, and
   the cached policy has previously been successfully applied, temporarily fail
   the message.
4. Upon message retries, a message MAY be permanently failed following first
   checking for the presence of a new policy (as indicated by the `id` field in
   the `_mta_sts` TXT record).

# IANA Considerations

A new .well-known URI will be registered in the Well-Known URIs registry as
described below:

URI Suffix: mta-sts.json
Change Controller: IETF

# Security Considerations

SMTP Strict Transport Security attempts to protect against an active attacker
who wishes to intercept or tamper with mail between hosts who support STARTTLS.
There are two classes of attacks considered:

1. Foiling TLS negotiation, for example by deleting the "250 STARTTLS" response
   from a server or altering TLS session negotiation. This would result in the
   SMTP session occurring over plaintext, despite both parties supporting TLS.

2. Impersonating the destination mail server, whereby the sender might deliver
   the message to an impostor, who could then monitor and/or modify messages
   despite opportunistic TLS. This impersonation could be accomplished by
   spoofing the DNS MX record for the recipient domain, or by redirecting client
   connections intended for the legitimate recipient server (for example, by
   altering BGP routing tables).

SMTP Strict Transport Security relies on certificate validation via PKIX based TLS
identity checking [@!RFC6125]. Attackers who are able to obtain a valid certificate
for the targeted recipient mail service (e.g. by compromising a certificate authority)
are thus able to circumvent STS authentication.

Since we use DNS TXT record for policy discovery, an attacker who is able to
block DNS responses can suppress the discovery of an STS Policy, making the
Policy Domain appear not to have an STS Policy. The caching model described in
_Policy_ _Expirations_ is designed to resist this attack.

We additionally consider the Denial of Service risk posed by an attacker who can
modify the DNS records for a victim domain. Absent SMTP STS, such an attacker
can cause a sending MTA to cache invalid MX records for a long TTL. With SMTP
STS, the attacker can additionally advertise a new SMTP STS policy with
never-satisfied `mx` constraints and a long `max_age`.

This attack is mitigated in part by the ability of a victim domain to (at any
time) publish a new policy updating or revoking the cached, malicious policy;
this does, however, require the victim domain to both obtain a valid CA-signed
certificate and to understand and properly configure SMTP STS.

Similarly, we consider the possibilty of domains that deliberately allow
untrusted users to serve untrusted content on user-specified subdomains. In some
cases (e.g. the service Tumblr.com) this takes the form of providing HTTPS
hosting of user-registered subdomains; in other cases (e.g. dynamic DNS
providers) this takes the form of allowing untrusted users to register custom
DNS records at the provider's domain.

In these cases, there is a risk that untrusted users would be able to serve
custom content at the `mta-sts` host, including serving an illegitimate SMTP STS
policy.  We believe this attack is mitigated in part by the need for the
attacker to also serve the `_mta_sts` TXT record on the same domain--something
not, to our knowledge, widely provided to untrusted users--and by the
aforementioned ability for a victim domain to revoke an invalid policy at any
future date.

Even if an attacker cannot modify a served policy, the potential exists for
configurations that allow attackers on the same domain to receive mail for that
domain. For example, an easy configuration option when authoring an STS Policy
for `example.com` is to set the `mx` equal to `*.example.com`; recipient domains
must consider in this case the risk that any user possessing a valid hostname
and CA-signed certificate (for example, `dhcp-123.example.com`) will, from the
perspective of STS Policy validation, be a valid MX host for that domain.

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

# Appendix 1: Delivery Pseudocode

Assume a persistent per-recipient-domain cache of an ordered list of
```
{
  STSPolicy policy
  boolean was_successfully_applied
  string version_id
}
```

Delivery to a given domain looks like

```
function attempt_policy(policy) {
  for each MX in MX candidates {
    if MX matches policy "mx" list {
      connect to MX
      if MX certificate is valid {
        deliver to MX
        return True
      }
    }
  }
  return False
}

if unexpired policies exists in cache {
  for policy in unexpired policies {
    if attempt_policy(policy) {
      set policy "was_successfully_applied" to True
      remove any older policies from cache
      return
    }
  }
  if any unexpired policies "was_successfully_applied" and mode is "enforce" {
    temp fail message
  }
}

if TXT record exists for recipient domain and
   (domain not in cache or
    cached policy version_id != TXT version_id) {
  attempt to fetch new policy via HTTPS
  set policy "was_successfully_applied" to False
  prepend policy to cached list of policies for recipient domain
}
```

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
_mta_sts  IN TXT ( "v=STSv1; id=20160831085700Z;" )
~~~~~~~~~

STS policy served from HTTPS endpoint of the policy (recipient) domain, and
is authenticated using the Web PKI mechanism. The policy is fetched using HTTP
GET method.

~~~~~~~~~
{
  "version": "STSv1",
  "mode": "report",
  "mx": ["*.mail.example.com"],
  "max_age": 123456
}

~~~~~~~~~

{backmatter}
