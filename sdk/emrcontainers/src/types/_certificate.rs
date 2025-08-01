// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The entity representing certificate data generated for managed endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Certificate {
    /// <p>The ARN of the certificate generated for managed endpoint.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The base64 encoded PEM certificate data generated for managed endpoint.</p>
    pub certificate_data: ::std::option::Option<::std::string::String>,
}
impl Certificate {
    /// <p>The ARN of the certificate generated for managed endpoint.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The base64 encoded PEM certificate data generated for managed endpoint.</p>
    pub fn certificate_data(&self) -> ::std::option::Option<&str> {
        self.certificate_data.as_deref()
    }
}
impl Certificate {
    /// Creates a new builder-style object to manufacture [`Certificate`](crate::types::Certificate).
    pub fn builder() -> crate::types::builders::CertificateBuilder {
        crate::types::builders::CertificateBuilder::default()
    }
}

/// A builder for [`Certificate`](crate::types::Certificate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CertificateBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_data: ::std::option::Option<::std::string::String>,
}
impl CertificateBuilder {
    /// <p>The ARN of the certificate generated for managed endpoint.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the certificate generated for managed endpoint.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The ARN of the certificate generated for managed endpoint.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>The base64 encoded PEM certificate data generated for managed endpoint.</p>
    pub fn certificate_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The base64 encoded PEM certificate data generated for managed endpoint.</p>
    pub fn set_certificate_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_data = input;
        self
    }
    /// <p>The base64 encoded PEM certificate data generated for managed endpoint.</p>
    pub fn get_certificate_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_data
    }
    /// Consumes the builder and constructs a [`Certificate`](crate::types::Certificate).
    pub fn build(self) -> crate::types::Certificate {
        crate::types::Certificate {
            certificate_arn: self.certificate_arn,
            certificate_data: self.certificate_data,
        }
    }
}
