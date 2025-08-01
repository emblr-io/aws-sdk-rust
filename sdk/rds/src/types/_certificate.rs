// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A CA certificate for an Amazon Web Services account.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html">Using SSL/TLS to encrypt a connection to a DB instance</a> in the <i>Amazon RDS User Guide</i> and <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.SSL.html"> Using SSL/TLS to encrypt a connection to a DB cluster</a> in the <i>Amazon Aurora User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Certificate {
    /// <p>The unique key that identifies a certificate.</p>
    pub certificate_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of the certificate.</p>
    pub certificate_type: ::std::option::Option<::std::string::String>,
    /// <p>The thumbprint of the certificate.</p>
    pub thumbprint: ::std::option::Option<::std::string::String>,
    /// <p>The starting date from which the certificate is valid.</p>
    pub valid_from: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The final date that the certificate continues to be valid.</p>
    pub valid_till: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) for the certificate.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether there is an override for the default certificate identifier.</p>
    pub customer_override: ::std::option::Option<bool>,
    /// <p>If there is an override for the default certificate identifier, when the override expires.</p>
    pub customer_override_valid_till: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl Certificate {
    /// <p>The unique key that identifies a certificate.</p>
    pub fn certificate_identifier(&self) -> ::std::option::Option<&str> {
        self.certificate_identifier.as_deref()
    }
    /// <p>The type of the certificate.</p>
    pub fn certificate_type(&self) -> ::std::option::Option<&str> {
        self.certificate_type.as_deref()
    }
    /// <p>The thumbprint of the certificate.</p>
    pub fn thumbprint(&self) -> ::std::option::Option<&str> {
        self.thumbprint.as_deref()
    }
    /// <p>The starting date from which the certificate is valid.</p>
    pub fn valid_from(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.valid_from.as_ref()
    }
    /// <p>The final date that the certificate continues to be valid.</p>
    pub fn valid_till(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.valid_till.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the certificate.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>Indicates whether there is an override for the default certificate identifier.</p>
    pub fn customer_override(&self) -> ::std::option::Option<bool> {
        self.customer_override
    }
    /// <p>If there is an override for the default certificate identifier, when the override expires.</p>
    pub fn customer_override_valid_till(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.customer_override_valid_till.as_ref()
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
    pub(crate) certificate_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_type: ::std::option::Option<::std::string::String>,
    pub(crate) thumbprint: ::std::option::Option<::std::string::String>,
    pub(crate) valid_from: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) valid_till: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) customer_override: ::std::option::Option<bool>,
    pub(crate) customer_override_valid_till: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CertificateBuilder {
    /// <p>The unique key that identifies a certificate.</p>
    pub fn certificate_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique key that identifies a certificate.</p>
    pub fn set_certificate_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_identifier = input;
        self
    }
    /// <p>The unique key that identifies a certificate.</p>
    pub fn get_certificate_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_identifier
    }
    /// <p>The type of the certificate.</p>
    pub fn certificate_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the certificate.</p>
    pub fn set_certificate_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_type = input;
        self
    }
    /// <p>The type of the certificate.</p>
    pub fn get_certificate_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_type
    }
    /// <p>The thumbprint of the certificate.</p>
    pub fn thumbprint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thumbprint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thumbprint of the certificate.</p>
    pub fn set_thumbprint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thumbprint = input;
        self
    }
    /// <p>The thumbprint of the certificate.</p>
    pub fn get_thumbprint(&self) -> &::std::option::Option<::std::string::String> {
        &self.thumbprint
    }
    /// <p>The starting date from which the certificate is valid.</p>
    pub fn valid_from(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.valid_from = ::std::option::Option::Some(input);
        self
    }
    /// <p>The starting date from which the certificate is valid.</p>
    pub fn set_valid_from(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.valid_from = input;
        self
    }
    /// <p>The starting date from which the certificate is valid.</p>
    pub fn get_valid_from(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.valid_from
    }
    /// <p>The final date that the certificate continues to be valid.</p>
    pub fn valid_till(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.valid_till = ::std::option::Option::Some(input);
        self
    }
    /// <p>The final date that the certificate continues to be valid.</p>
    pub fn set_valid_till(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.valid_till = input;
        self
    }
    /// <p>The final date that the certificate continues to be valid.</p>
    pub fn get_valid_till(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.valid_till
    }
    /// <p>The Amazon Resource Name (ARN) for the certificate.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the certificate.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the certificate.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>Indicates whether there is an override for the default certificate identifier.</p>
    pub fn customer_override(mut self, input: bool) -> Self {
        self.customer_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether there is an override for the default certificate identifier.</p>
    pub fn set_customer_override(mut self, input: ::std::option::Option<bool>) -> Self {
        self.customer_override = input;
        self
    }
    /// <p>Indicates whether there is an override for the default certificate identifier.</p>
    pub fn get_customer_override(&self) -> &::std::option::Option<bool> {
        &self.customer_override
    }
    /// <p>If there is an override for the default certificate identifier, when the override expires.</p>
    pub fn customer_override_valid_till(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.customer_override_valid_till = ::std::option::Option::Some(input);
        self
    }
    /// <p>If there is an override for the default certificate identifier, when the override expires.</p>
    pub fn set_customer_override_valid_till(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.customer_override_valid_till = input;
        self
    }
    /// <p>If there is an override for the default certificate identifier, when the override expires.</p>
    pub fn get_customer_override_valid_till(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.customer_override_valid_till
    }
    /// Consumes the builder and constructs a [`Certificate`](crate::types::Certificate).
    pub fn build(self) -> crate::types::Certificate {
        crate::types::Certificate {
            certificate_identifier: self.certificate_identifier,
            certificate_type: self.certificate_type,
            thumbprint: self.thumbprint,
            valid_from: self.valid_from,
            valid_till: self.valid_till,
            certificate_arn: self.certificate_arn,
            customer_override: self.customer_override,
            customer_override_valid_till: self.customer_override_valid_till,
        }
    }
}
