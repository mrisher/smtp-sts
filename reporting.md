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
   initials="DM"
   surname="Margolis"
   fullname="Daniel Margolis"
   organization="Google, Inc"
     [author.address]
     email="dmargolis (at) google.com"
   [[author]]
   initials="AB"
   surname="Brotman"
   fullname="Alexander Brotman"
   organization="Comcast, Inc"
     [author.address]
     email="alexander_brotman (at) cable.comcast (dot com)"
   [[author]]
   initials="BR"
   surname="Ramakrishnan"
   fullname="Binu Ramakrishnan"
   organization="Yahoo!, Inc"
     [author.address]
     email="rbinu (at) yahoo-inc (dot com)"
   [[author]]
   initials="JJ"
   surname="Jones"
   fullname="Janet Jones"
   organization="Microsoft, Inc"
     [author.address]
     email="janet.jones (at) microsoft (dot com)"
   [[author]]
   initials="MR"
   surname="Risher"
   fullname="Mark Risher"
   organization="Google, Inc"
     [author.address]
     email="risher (at) google (dot com)"

%%%

.# Abstract

SMTP Mail Transfer Agents often conduct encrypted communication on the Internet
through the use of Transport Layer Security (TLS). Due to the opportunistic
nature of the STARTTLS protocol, malicious and misconfigured intermediaries can
interfere with the successful establishment of suitable encryption, and such
interference is not always detectable by the receiving server. This document
provides transparency into failures in the SMTP MTA Strict Transport Security
policy [@!TBD], negotiation of STARTTLS [@!RFC3207], and the DNS-Based
Authentication of Named Entities (DANE, [@!RFC6698]).


{mainmatter}

# Introduction

The STARTTLS extension to SMTP [@!RFC3207] allows SMTP clients and hosts to
establish secure SMTP sessions over TLS. The protocol design is based
on "Opportunistic Security" (OS) [@!RFC7435], which provides interoperability for clients that do not support it, but means that  any attacker who can delete
parts of the SMTP session (such as the "250 STARTTLS" response) or who can
redirect the entire SMTP session (perhaps by overwriting the resolved MX record
of the delivery domain) can perform such a downgrade or interception attack.

Because such "downgrade attacks" are not necessarily apparent to the receiving MTA, this document defines a mechanism for sending domains to report on failures at multiple parts of the MTA-to-MTA conversation. 

Specifically, this document defines a reporting schema that covers:

   *   


## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when
they appear in this document, are to be interpreted as described in [@!RFC2119].

We also define the following terms for further use in this document:

* STS Policy: A definition of the expected TLS availability and behavior, as
  well as the desired actions for a given domain when a sending MTA encounters
  different results.
* Policy Domain: The domain against which an STS Policy is defined.
* Sending MTA: The MTA initiating the delivery of an email message.

# Related Technologies

  * The Public Key Pinning Extension for HTTP [@!RFC7469] contains a JSON-based definition for reporting individual pin validation failures. 
  * The Domain-based Message Authentication, Reporting, and Conformance (DMARC) [@!RFC7489] contains an XML-based reporting format for aggregate and detailed email delivery errors. 

# Failure Reporting

Aggregate statistics on policy failures MAY be reported to the URI indicated
in the `aggregate-report-uri` field of the policy. SMTP TLSRPT reports contain information about policy failures to allow diagnosis of misconfigurations and malicious activity.

(There may also be a need for enabling more detailed "forensic" reporting during
initial stages of a deployment. To address this, the authors consider the
possibility of an optional additional "forensic reporting mode" in which more
details--such as certificate chains and MTA banners--may be reported. See the
section _Future_ _Work_ for more details.)

The supported URI schemes are `mailto` and `https`. 

   * In the case of `https`, reports should be submitted via POST ([@!RFC2818])
     to the specified URI.

   * In the case of `mailto`, reports should be submitted to the specified
     email address. When sending failure reports via SMTP, sending MTAs MUST
     NOT honor SMTP STS or DANE TLSA failures.

Aggregate reports contain the following fields:

* _Report metadata_: 
	* The organization responsible for the report
	* Contact information for one or more responsible parties for the contents of the report
	* A unique identifier for the report
	* The reporting date range for the report
* _Policy specifics_, consisting of one of the following:
	* The SMTP MTA STS policy applied (as a string)
	* The DANE TLSA record applied (as a string)
* _Aggregate counts_, comprising _result type_, _sending MTA IP_, _receiving MTA hostname_, _message count_, and an optional _additional information_ field containing a URI for recipients to review further information on a failure type.

Note that the failure types are non-exclusive; an aggregate report MAY contain
overlapping `counts` of failure types where a single send attempt encountered
multiple errors.


## Result Types

The list of result types will start with the minimal set below, and is expected
  to grow over time based on real-world experience. The initial set is:

### Success Type
  * `success`: This indicates that the sending MTA was able to successfully negotiate a policy-compliant TLS connection, and serves to provide a "heartbeat" to receiving domains that reporting is functional and tabulating correctly.
  
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

# IANA Considerations

There are no IANA considerations at this time.

# Security Considerations

SMTP TLS Reporting provides transparency into misconfigurations and attempts to
intercept or tamper with mail between hosts who support STARTTLS. There are several security risks presented by the existence of this reporting channel:

  * _Flooding of the `aggregate-report-uri` endpoint_: An attacker could flood the endpoint and prevent the receiving domain from accepting additional reports. This type of Denial-of-Service attack would limit visibility into STARTTLS failures, leaving the receiving domain blind to an ongoing attack.
  * _Untrusted content_: An attacker could inject malicious code into the report, opening a vulnerability in the receiving domain. Implementers are advised to take precautions against evaluating the contents of the report.


# Appendix 1: Validation Pseudocode
~~~~~~~~~
policy = policy_from_cache()
if not policy or is_expired(policy):
  policy = policy_from_dns()  // fetch and authenticate!
  update_cache = true
if policy:
  if invalid_mx_or_tls(policy):  // check MX and TLS cert
    if rua:
      generate_report()
    if p_reject():
      policy = policy_from_dns()  // fetch and authenticate #2!
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
solicit aggregate feedback from receivers without affecting how the messages
are processed, in order to:

* Confirm that its legitimate messages are sent over TLS

* Verify the validity of the certificates

* Verify what ciphers are in use

* Determine how many messages would be affected by a strict policy

~~~~~~~~~
_smtp_sts  IN TXT ( "v=STS1; m=report; "
                     "mx=*mail.example.com; "
                     "a=dnssec; c=webpki; e=123456"
                     "rua=mailto:sts-feedback@example.com" )
~~~~~~~~~

## Example 2

Similar to Example 1 above, but in _enforce_ mode. Since the auth field 'a' is
webpki, the sender will authenticate the policy by making a HTTPS request to:
https://policy._smtp_sts.example.com/current and compare the content with the
policy in the DNS. example.com is the recipient's domain.

~~~~~~~~~
_smtp_sts  IN TXT ( "v=STS1; m=enforce; "
                     "mx=*mail.example.com; "
                     "a=webpki; c=webpki; e=123456"
                     "rua=mailto:sts-feedback@example.com" )
~~~~~~~~~

# Appendix 3: XML Schema for Failure Reports
~~~~~~~~~

<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
    targetNamespace="http://www.example.org/smtp-sts-xml/0.1"
    xmlns:tns="http://www.example.org/smtp-sts-xml/0.1">
   <!-- The time range in UTC covered by messages in this report,
        specified in seconds since epoch. -->
   <xs:complexType name="DateRangeType">
     <xs:all>
       <xs:element name="begin" type="xs:integer"/>
       <xs:element name="end" type="xs:integer"/>
     </xs:all>
   </xs:complexType>

   <!-- Report generator metadata. -->
   <xs:complexType name="ReportMetadataType">
     <xs:sequence>
       <xs:element name="org_name" type="xs:string"/>
       <xs:element name="email" type="xs:string"/>
       <xs:element name="extra_contact_info" type="xs:string"
                   minOccurs="0"/>
       <xs:element name="report_id" type="xs:string"/>
       <xs:element name="date_range" type="tns:DateRangeType"/>
     </xs:sequence>
   </xs:complexType>


   <!-- The constraints applied in a policy -->
   <xs:simpleType name="ConstraintType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="WebPKI"/>
       <xs:enumeration value="TLSA"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- The policy that was applied at send time. -->
   <xs:complexType name="AppliedPolicyType">
     <xs:all>
       <xs:element name="domain" type="xs:string"/>
       <xs:element name="mx" type="xs:string"
           minOccurs="1" />
       <xs:element name="constraint" type="tns:ConstraintType"/>
       <xs:element name="policy_id" type="xs:string"
     </xs:all>
   </xs:complexType>

   <!-- The possible failure types applied in a policy -->
   <xs:simpleType name="FailureType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="MxMismatch"/>
       <xs:enumeration value="InvalidCertificate"/>
       <xs:enumeration value="ExpiredCertificate"/>
       <xs:enumeration value="StarttlsNotSupported"/>
       <xs:enumeration value="TlsaInvalid"/>
       <xs:enumeration value="DnssecInvalid"/>
       <xs:enumeration value="SenderDoesNotSupportValidationMethod"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- The possible enforcement level: whether the reporter also drops
        messages -->
   <xs:simpleType name="EnforcementLevelType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="ReportOnly"/>
       <xs:enumeration value="Reject"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- Record for individual failure types. -->
   <xs:complexType name="FailureRecordType">
     <xs:all>
       <xs:element name="failure" type="tns:FailureType"/>
       <xs:element name="count" type="xs:integer"/>
       <xs:element name="hostname" type="xs:string"/>
       <xs:element name="connectedIp" type="xs:string" minOccurs="0"/>
       <xs:element name="sourceIp" type="xs:string" minOccurs="0"/>
     </xs:all>
   </xs:complexType>

    <!-- Parent -->
   <xs:element name="feedback">
     <xs:complexType>
       <xs:sequence>
         <xs:element name="version"
                     type="xs:decimal"/>
         <xs:element name="report_metadata"
                     type="tns:ReportMetadataType"/>
         <xs:element name="applied_policy"
                     type="tns:AppliedPolicyType"/>
   <xs:element name="enforcement_level"
   type="tns:EnforcementLevelType"/>
         <xs:element name="record" type="tns:FailureRecordType"
                     maxOccurs="unbounded"/>
       </xs:sequence>
     </xs:complexType>
   </xs:element>
</xs:schema>
~~~~~~~~~

# Appendix 4: Example report
~~~~~~~~~
<feedback xmlns="http://www.example.org/smtp-sts-xml/0.1">
  <version>1</version>
  <report_metadata>
    <org_name>Company-X</org_name>
    <email>sts-reporting@company-x.com</email>
    <extra_contact_info></extra_contact_info>
    <report_id>12345</report_id>
    <date_range><begin>1439227624</begin>
    <end>1439313998</end></date_range>
    </report_metadata>
  <applied_policy>
    <domain>company-y.com</domain>
    <mx>*.mx.mail.company-y.com</mx>
    <constraint>WebPKI</constraint>
    <policy_id>33a0fe07d5c5359c</policy_id>
  </applied_policy>
   <enforcement_level>ReportOnly</enforcement_level>
  <record>
      <failure>ExpiredCertificate</failure>
      <count>13128</count>
      <hostname>mta7.mx.mail.company-y.com</hostname>
      <connectedIp>98.136.216.25</connectedIp>
  </record>
  <record>
      <failure>StarttlsNotSupported</failure>
      <count>19</count>
      <hostname>mta7.mx.mail.company-y.com</hostname>
      <connectedIp>98.22.33.99</connectedIp>
  </record>
</feedback>
~~~~~~~~~

{backmatter}
