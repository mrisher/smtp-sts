%%%

   Title = "SMTP TLS Reporting"
   abbrev = "SMTP-TLSRPT"
   category = "std"
   docName = "draft-ietf-uta-smtp-tlsrpt-00"
   ipr = "trust200902"
   area = "Applications"
   workgroup = "Using TLS in Applications"
   keyword = [""]

   date = 2016-04-18T00:00:00Z

   [[author]]
   initials="D."
   surname="Margolis"
   fullname="Daniel Margolis"
   organization="Google, Inc"
     [author.address]
     email="dmargolis (at) google.com"
   [[author]]
   initials="A."
   surname="Brotman"
   fullname="Alexander Brotman"
   organization="Comcast, Inc"
     [author.address]
     email="alexander_brotman (at) cable.comcast (dot com)"
   [[author]]
   initials="B."
   surname="Ramakrishnan"
   fullname="Binu Ramakrishnan"
   organization="Yahoo!, Inc"
     [author.address]
     email="rbinu (at) yahoo-inc (dot com)"
   [[author]]
   initials="J."
   surname="Jones"
   fullname="Janet Jones"
   organization="Microsoft, Inc"
     [author.address]
     email="janet.jones (at) microsoft (dot com)"
   [[author]]
   initials="M."
   surname="Risher"
   fullname="Mark Risher"
   organization="Google, Inc"
     [author.address]
     email="risher (at) google (dot com)"

%%%

.# Abstract

SMTP Mail Transfer Agents often conduct encrypted communication through the use
of Transport Layer Security (TLS). Because the STARTTLS protocol employs
opportunistic encryption, "Man-in-the-Middle" intermediaries can interfere with
the successful establishment of suitable encryption in ways that may not be
detectable by the receiving server. This document provides transparency into
failures in SMTP MTA Strict Transport Security (TODO: Add ref), STARTTLS
[@!RFC3207], and the DNS-Based Authentication of Named Entities (DANE,
[@!RFC6698]).


{mainmatter}

# Introduction

The STARTTLS extension to SMTP [@!RFC3207] allows SMTP clients and hosts to
establish secure SMTP sessions over TLS. The protocol design is based on
"Opportunistic Security" (OS) [@!RFC7435], which provides interoperability for
clients that do not support it, but means that any attacker who can delete
parts of the SMTP session (such as the "250 STARTTLS" response) or who can
redirect the entire SMTP session (perhaps by overwriting the resolved MX record
of the delivery domain) can perform such a downgrade or interception attack.

Because such "downgrade attacks" are not necessarily apparent to the receiving
MTA, this document defines a mechanism for sending domains to report on
failures at multiple parts of the MTA-to-MTA conversation.

Specifically, this document defines a reporting schema that covers failures 
in routing, STARTTLS negotiation, and both DANE [@!RFC7671] and STS (TODO: Add
ref) policy validation errors.

Implementers establish a policy by publishing a TXT record in the DNS which
instructs comliant sending MTAs to deliver reports of delivery and STARTTLS
failures in the appropriate format to the specified endpoint.

This document is intended as a companion to the specification for SMTP MTA 
Strict Transport Security (MTA-STS, TODO: Add ref).

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when
they appear in this document, are to be interpreted as described in [@!RFC2119].

We also define the following terms for further use in this document:

  * STS Policy: A definition of the expected TLS availability and behavior, as
    well as the desired actions for a given domain when a sending MTA encounters
    different results.
  * TLSRPT Policy: A policy detailing the endpoint for sending MTAs should to
    deliver reports 
  * Policy Domain: The domain against which an STS Policy is defined.
  * Sending MTA: The MTA initiating the delivery of an email message.

# Related Technologies
  * This document is intended as a companion to the specification for SMTP MTA
    Strict Transport Security (MTA-STS, TODO: Add ref).
  * The Public Key Pinning Extension for HTTP [@!RFC7469] contains a JSON-based
    definition for reporting individual pin validation failures.
  * The Domain-based Message Authentication, Reporting, and Conformance (DMARC)
    [@!RFC7489] contains an XML-based reporting format for aggregate and
    detailed email delivery errors.

# Reporting Policy

SMTP TLSRPT policies are distributed via DNS from the Policy Domain's zone,
either through a new resource record, or as TXT records (similar to DMARC
policies) under the name `_smtp_tlsrpt`. (Current implementations deploy as TXT
records.) For example, for the Policy Domain `example.com`, the recipient's
SMTP STS policy can be retrieved from `_smtp_tlsrpt.example.com`.

(Future implementations may move to alternate methods of policy discovery or
distribution. See the section _Future_ _Work_ for more discussion.)

Policies consist of the following directives:

   * `version`: This value MUST be equal to `TLSRPT1`.
   * `aggregate-report-uri`: A URI specifying the endpoint to which aggregate
     information about policy failures should be sent (see the section
     _Reporting Schema_ for more information). Two URI schemes are supported:
     `mailto` and `https`.
	 * In the case of `https`, reports should be submitted via POST
     ([@!RFC2818]) to the specified URI.
 	 * In the case of `mailto`, reports should be submitted to the specified
     email address. When sending failure reports via SMTP, sending MTAs MUST
     NOT honor SMTP STS or DANE TLSA failures.
   * `detailed-report-uri`: Future use. (There may also be a need for enabling
     more detailed "forensic" reporting during initial stages of a deployment.
     To address this, the authors consider the possibility of an optional
     additional "forensic reporting mode" in which more details--such as
     certificate chains and MTA banners--may be reported. See the section
     _Future_ _Work_ for more details.)


## Example Reporting Policy

### Report using MAILTO:

```_smtp_tlsrpt.mail.example.com. IN TXT \
		"version:TLSRPT1;aggregate-report-uri:mailto:reports@example.com"
```

### Report using HTTPS:

```_smtp_tlsrpt.mail.example.com. IN TXT \
		"version:TLSRPT1; \
		aggregate-report-uri:https://reporting.example.com/v1/tlsrpt"
```


# Reporting Schema

Aggregate reports contain the following fields:

* _Report metadata_: 
	* The organization responsible for the report
	* Contact information for one or more responsible parties for the contents 
	of the report
	* A unique identifier for the report
	* The reporting date range for the report
* _Applied policy_, consisting of: 
	* One of the following policy types:
		* The SMTP MTA STS policy applied (as a string)
		* The DANE TLSA record applied (as a string)
	* The domain for which the policy is applied
	* The MX host
	* An identifier for the policy (where applicable)
* _Aggregate counts_, comprising _result type_, _sending MTA IP_, _receiving
  MTA hostname_, _message count_, and an optional _additional information_
  field containing a URI for recipients to review further information on a
  failure type.



Note that the failure types are non-exclusive; an aggregate report MAY contain
overlapping `counts` of failure types where a single send attempt encountered
multiple errors.


## Result Types

The list of result types will start with the minimal set below, and is expected
  to grow over time based on real-world experience. The initial set is:

### Success Type
  * `success`: This indicates that the sending MTA was able to successfully
    negotiate a policy-compliant TLS connection, and serves to provide a
    "heartbeat" to receiving domains that reporting is functional and
    tabulating correctly.

  
### Routing Failures
  * `mx-mismatch`: This indicates that the MX resolved for the recipient domain
    did not match the MX constraint specified in the policy.
  * `certificate-mismatch`: This indicates that the certificate presented by the
    receiving MX did not match the MX hostname

### Negotiation Failures

  * `starttls-not-supported`: This indicates that the recipient MX did not
    support STARTTLS.
  * `invalid-certificate`: This indicates that the certificate presented by the
    receiving MX did not validate according to the policy validation constraint.
    (Either it was not signed by a trusted CA or did not match the DANE TLSA
    record for the recipient MX.)
  * `expired-certificate`: This indicates that the certificate has expired.

#### DANE-specific Policy Failures
  * `tlsa-invalid`: This indicates a validation error for Policy Domain
    specifying "tlsa" validation.
  * `dnssec-invalid`: This indicates a failure to validate DNS records for a
    Policy Domain with a published "tlsa" record.

#### STS-specific Policy Failures
  * `sts-invalid`: This indicates a validation error for Policy Domain
    specifying "STS" validation.

  * sender-does-not-support-validation-method: This indicates the sending system
    can never validate using the requested validation mechanism.


# Reporting Delegation

   It is possible to specify destinations for the different reports that
   are outside the authority of the Policy Domain making the request.
   This allows domains that do not operate mail servers to request
   reports and have them go someplace that is able to receive and
   process them.

   Without checks, this would allow a bad actor to publish a TLS-RPT policy
   record that requests that reports be sent to a victim address, potentially
   causing the victim to be flooded with unwanted reports. Therefore, a
   verification mechanism is included as inspired by Section 7.1 from 
   [@!RFC7489].

   When a sending MTA discovers a TLS-RPT policy in the DNS, and the
   Organizational Domain at which that record was discovered is not identical to
   the Organizational Domain of the host part of the authority component of a
   [URI] specified in the "aggregate-report-uri" or "detailed-report-uri" tag,
   the following verification steps are to be taken:

   1.  Extract the host portion of the authority component of the URI.
       Call this the "destination host", as it refers to a Report
       Receiver.

   2.  Prepend the string "_report._tlsrpt".

   3.  Prepend the domain name from which the policy was retrieved,
       after conversion to an A-label if needed.

   4.  Query the DNS for a TXT record at the constructed name.  If the
       result of this request is a temporary DNS error of some kind
       (e.g., a timeout), the sending domain MAY elect to temporarily
       fail the delivery so the verification test can be repeated later.

   5.  For each record returned, parse the result as a series of
       "tag:value" pairs, i.e., the same overall format as the policy
       record.  In particular, the "version:TLSRPT1" tag is
       mandatory and MUST appear first in the list.  Discard any that do
       not pass this test.

   6.  If the result includes no TXT resource records that pass basic
       parsing, a positive determination of the external reporting
       relationship cannot be made; stop.

   7.  If at least one TXT resource record remains in the set after
       parsing, then the external reporting arrangement was authorized
       by the Policy Domain.

   8. If a "aggregate-report-uri" or "detailed-report-uri" tag is thus
   discovered, replace the corresponding value extracted with the one found in
   this record. This permits the Policy Domain to override the report
   destination. However, to prevent loops or indirect abuse, the overriding URI
   MUST use the same destination host from the first step.

``` 
   **TODO FIX to match TLSRPT (instead of DMARC) if we think we need this.**

   For example, if a TLSRPT policy query for "blue.example.com" contained
   "rua=mailto:reports@red.example.net", the host extracted from the
   latter ("red.example.net") does not match "blue.example.com", so this
   procedure is enacted.  A TXT query for
   "blue.example.com._report._dmarc.red.example.net" is issued.  If a
   single reply comes back containing a tag of "v=DMARC1", then the
   relationship between the two is confirmed.  Moreover,
   "red.example.net" has the opportunity to override the report
   destination requested by "blue.example.com" if needed.

   Where the above algorithm fails to confirm that the external
   reporting was authorized by the Report Receiver, the URI MUST be
   ignored by the Mail Receiver generating the report.  Further, if the
   confirming record includes a URI whose host is again different than
   the domain publishing that override, the Mail Receiver generating the
   report MUST NOT generate a report to either the original or the
   override URI.

   A Report Receiver publishes such a record in its DNS if it wishes to
   receive reports for other domains.

   A Report Receiver that is willing to receive reports for any domain
   can use a wildcard DNS record.  For example, a TXT resource record at
   "*._report._dmarc.example.com" containing at least "v=DMARC1"
   confirms that example.com is willing to receive DMARC reports for any
   domain.

   If the Report Receiver is overcome by volume, it can simply remove
   the confirming DNS record.  However, due to positive caching, the
   change could take as long as the time-to-live (TTL) on the record to
   go into effect.

   A Mail Receiver might decide not to enact this procedure if, for
   example, it relies on a local list of domains for which external
   reporting addresses are permitted.
```


# IANA Considerations

There are no IANA considerations at this time.

# Security Considerations

SMTP TLS Reporting provides transparency into misconfigurations and attempts to
intercept or tamper with mail between hosts who support STARTTLS. There are
several security risks presented by the existence of this reporting channel:

  * _Flooding of the_ `aggregate-report-uri` _endpoint_: An attacker could
    flood the endpoint and prevent the receiving domain from accepting
    additional reports. This type of Denial-of-Service attack would limit
    visibility into STARTTLS failures, leaving the receiving domain blind to an
    ongoing attack.

  * _Untrusted content_: An attacker could inject malicious code into the
    report, opening a vulnerability in the receiving domain. Implementers are
    advised to take precautions against evaluating the contents of the report.

  * _Report snooping_: An attacker could create a bogus TLSRPT record to
    receive statistics about a domain the attacker does not own. Since an
    attacker able to poison DNS is already able to receive counts of SMTP
    connections (and, in fact, actual SMTP message payloads) today, this does
    not present a significant new vulnerability.


# Appendix 1: JSON Report Schema

The JSON schema is derived from the HPKP JSON schema [@!RFC7469] (cf. Section 3)

```
{
  "organization-name": organization-name,
  "date-range": {
	"start-datetime": date-time,
	"end-datetime": date-time
  },
  "contact-info": email-address,
  "report-id": report-id,
  "applied-policy": {
	"policy-type": policy-type,
	"policy-string": policy-string,
	"policy-domain": domain,
	"mx-host": mx-host-pattern,
	"policy-id": policy-id
	},
  "report-items": [
	{
	  "result-type": result-type,
	  "sending-mta-ip": ip-address,
	  "receiving-mta-hostname": receiving-mta-hostname,
	  "message-count": message-count,
	  "additional-information": additional-info-uri
	}
  ]
}
```
Figure x: JSON Report Format

  * `organization-name`: The name of the organization responsible for the
    report. It is provided as a string.
  * `date-time`: The date-time indicates the start- and end-times for the
    report range. It is provided as a string formatted according to
   Section 5.6, "Internet Date/Time Format", of [@!RFC3339].
  * `email-address`: The contact information for a responsible party of the
    report. It is provided as a string formatted according to Section 3.4.1,
    "Addr-Spec", of [@!RFC5322].
  * `report-id`: A unique identifier for the report. Report authors may use
    whatever scheme they prefer to generate a unique identifier. It is provided
    as a string.
  * `policy-type`: The type of policy that was applied by the sending domain.
    Presently, the only two valid choices are `tlsa` and `sts`. It is provided
    as a string.
  * `policy-string`: The string serialization of the policy, whether TLSA
    record or STS policy. Any linefeeds from the original policy MUST be
    replaced with [SP]. TODO: Help with specifics.
  * `domain`: The Policy Domain upon which the policy was applied. For messages
    sent to `user@example.com` this field would contain `example.com`. It is
    provided as a string.
  * `mx-host-pattern`: The pattern of MX hostnames from the applied policy. It
    is provided as a string.
  * `policy-id`: The version number of the STS policy, or left blank for TLSA.
  * `result-type`: A value from the _Result Types_ section above.
  * `ip-address`: The IP address of the sending MTA that attempted the STARTTLS
    connection. It is provided as a string representation of an IPv4 or IPv6
    address.
  * `receiving-mta-hostname`: The hostname of the receiving MTA with which the
    sending MTA referenced in the `ip-address` field attempted to negotiate a
    STARTTLS connection.
  * `message-count`: The number of (attempted) messages that match the relevant
    `result-type` for this section.
  * `additional-info-uri`: An optional URI pointing to additional information
    around the relevant `result-type`. For example, this URI might host the
    complete certificate chain presented during an attempted STARTTLS session.


# Appendix 2: Example JSON Report
```
{
	"organization-name": "Company-X",
	"date-range": {
		"start-datetime": "2016-04-01T00:00:00Z",
		"end-datetime": "2016-04-01T23:59:59Z"
	},
	"contact-info": "sts-reporting@company-x.com",
	"report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
	"applied-policy": {
		"policy-type": "sts",
		"policy-string": "TODO: Add me",
		"policy-domain": "company-y.com",
		"mx-host": "*.mx.mail.company-y.com",
		"policy-id": "33a0fe07d5c5359c"
	},
	"report-items": [{
		"result-type": "ExpiredCertificate",
		"sending-mta-ip": "98.136.216.25",
		"receiving-mta-hostname": "mta7.mx.mail.company-y.com",
		"message-count": 13128
	}, {
		"result-type": "StarttlsNotSupported",
		"sending-mta-ip": "98.22.33.99",
		"receiving-mta-hostname": "mta7.mx.mail.company-y.com",
		"message-count": 19,
		"additional-information": "hxxps://reports.company-x.com/
                  report_info?id=5065427c-23d3#StarttlsNotSupported"
	}]
}
```

{backmatter}
