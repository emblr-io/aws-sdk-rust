// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A record of a presented X509 credential from a temporary credential request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CredentialSummary {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub seen_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The serial number of the certificate.</p>
    pub serial_number: ::std::option::Option<::std::string::String>,
    /// <p>The fully qualified domain name of the issuing certificate for the presented end-entity certificate.</p>
    pub issuer: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the credential is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>The PEM-encoded data of the certificate.</p>
    pub x509_certificate_data: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub failed: ::std::option::Option<bool>,
}
impl CredentialSummary {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn seen_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.seen_at.as_ref()
    }
    /// <p>The serial number of the certificate.</p>
    pub fn serial_number(&self) -> ::std::option::Option<&str> {
        self.serial_number.as_deref()
    }
    /// <p>The fully qualified domain name of the issuing certificate for the presented end-entity certificate.</p>
    pub fn issuer(&self) -> ::std::option::Option<&str> {
        self.issuer.as_deref()
    }
    /// <p>Indicates whether the credential is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>The PEM-encoded data of the certificate.</p>
    pub fn x509_certificate_data(&self) -> ::std::option::Option<&str> {
        self.x509_certificate_data.as_deref()
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn failed(&self) -> ::std::option::Option<bool> {
        self.failed
    }
}
impl CredentialSummary {
    /// Creates a new builder-style object to manufacture [`CredentialSummary`](crate::types::CredentialSummary).
    pub fn builder() -> crate::types::builders::CredentialSummaryBuilder {
        crate::types::builders::CredentialSummaryBuilder::default()
    }
}

/// A builder for [`CredentialSummary`](crate::types::CredentialSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CredentialSummaryBuilder {
    pub(crate) seen_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) issuer: ::std::option::Option<::std::string::String>,
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) x509_certificate_data: ::std::option::Option<::std::string::String>,
    pub(crate) failed: ::std::option::Option<bool>,
}
impl CredentialSummaryBuilder {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn seen_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.seen_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn set_seen_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.seen_at = input;
        self
    }
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn get_seen_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.seen_at
    }
    /// <p>The serial number of the certificate.</p>
    pub fn serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The serial number of the certificate.</p>
    pub fn set_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.serial_number = input;
        self
    }
    /// <p>The serial number of the certificate.</p>
    pub fn get_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.serial_number
    }
    /// <p>The fully qualified domain name of the issuing certificate for the presented end-entity certificate.</p>
    pub fn issuer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.issuer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified domain name of the issuing certificate for the presented end-entity certificate.</p>
    pub fn set_issuer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.issuer = input;
        self
    }
    /// <p>The fully qualified domain name of the issuing certificate for the presented end-entity certificate.</p>
    pub fn get_issuer(&self) -> &::std::option::Option<::std::string::String> {
        &self.issuer
    }
    /// <p>Indicates whether the credential is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the credential is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Indicates whether the credential is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The PEM-encoded data of the certificate.</p>
    pub fn x509_certificate_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.x509_certificate_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The PEM-encoded data of the certificate.</p>
    pub fn set_x509_certificate_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.x509_certificate_data = input;
        self
    }
    /// <p>The PEM-encoded data of the certificate.</p>
    pub fn get_x509_certificate_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.x509_certificate_data
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn failed(mut self, input: bool) -> Self {
        self.failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn set_failed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.failed = input;
        self
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn get_failed(&self) -> &::std::option::Option<bool> {
        &self.failed
    }
    /// Consumes the builder and constructs a [`CredentialSummary`](crate::types::CredentialSummary).
    pub fn build(self) -> crate::types::CredentialSummary {
        crate::types::CredentialSummary {
            seen_at: self.seen_at,
            serial_number: self.serial_number,
            issuer: self.issuer,
            enabled: self.enabled,
            x509_certificate_data: self.x509_certificate_data,
            failed: self.failed,
        }
    }
}
