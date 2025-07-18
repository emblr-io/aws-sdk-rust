// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a Transport Layer Security (TLS) validation context trust for an Certificate Manager certificate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TlsValidationContextAcmTrust {
    /// <p>One or more ACM Amazon Resource Name (ARN)s.</p>
    pub certificate_authority_arns: ::std::vec::Vec<::std::string::String>,
}
impl TlsValidationContextAcmTrust {
    /// <p>One or more ACM Amazon Resource Name (ARN)s.</p>
    pub fn certificate_authority_arns(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.certificate_authority_arns.deref()
    }
}
impl TlsValidationContextAcmTrust {
    /// Creates a new builder-style object to manufacture [`TlsValidationContextAcmTrust`](crate::types::TlsValidationContextAcmTrust).
    pub fn builder() -> crate::types::builders::TlsValidationContextAcmTrustBuilder {
        crate::types::builders::TlsValidationContextAcmTrustBuilder::default()
    }
}

/// A builder for [`TlsValidationContextAcmTrust`](crate::types::TlsValidationContextAcmTrust).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TlsValidationContextAcmTrustBuilder {
    pub(crate) certificate_authority_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TlsValidationContextAcmTrustBuilder {
    /// Appends an item to `certificate_authority_arns`.
    ///
    /// To override the contents of this collection use [`set_certificate_authority_arns`](Self::set_certificate_authority_arns).
    ///
    /// <p>One or more ACM Amazon Resource Name (ARN)s.</p>
    pub fn certificate_authority_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.certificate_authority_arns.unwrap_or_default();
        v.push(input.into());
        self.certificate_authority_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more ACM Amazon Resource Name (ARN)s.</p>
    pub fn set_certificate_authority_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.certificate_authority_arns = input;
        self
    }
    /// <p>One or more ACM Amazon Resource Name (ARN)s.</p>
    pub fn get_certificate_authority_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.certificate_authority_arns
    }
    /// Consumes the builder and constructs a [`TlsValidationContextAcmTrust`](crate::types::TlsValidationContextAcmTrust).
    /// This method will fail if any of the following fields are not set:
    /// - [`certificate_authority_arns`](crate::types::builders::TlsValidationContextAcmTrustBuilder::certificate_authority_arns)
    pub fn build(self) -> ::std::result::Result<crate::types::TlsValidationContextAcmTrust, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TlsValidationContextAcmTrust {
            certificate_authority_arns: self.certificate_authority_arns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "certificate_authority_arns",
                    "certificate_authority_arns was not specified but it is required when building TlsValidationContextAcmTrust",
                )
            })?,
        })
    }
}
