// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RevokeCertificateInput {
    /// <p>The Amazon Resource Name (ARN) of the public or private certificate that will be revoked. The ARN must have the following form:</p>
    /// <p><code>arn:aws:acm:region:account:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies why you revoked the certificate.</p>
    pub revocation_reason: ::std::option::Option<crate::types::RevocationReason>,
}
impl RevokeCertificateInput {
    /// <p>The Amazon Resource Name (ARN) of the public or private certificate that will be revoked. The ARN must have the following form:</p>
    /// <p><code>arn:aws:acm:region:account:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>Specifies why you revoked the certificate.</p>
    pub fn revocation_reason(&self) -> ::std::option::Option<&crate::types::RevocationReason> {
        self.revocation_reason.as_ref()
    }
}
impl RevokeCertificateInput {
    /// Creates a new builder-style object to manufacture [`RevokeCertificateInput`](crate::operation::revoke_certificate::RevokeCertificateInput).
    pub fn builder() -> crate::operation::revoke_certificate::builders::RevokeCertificateInputBuilder {
        crate::operation::revoke_certificate::builders::RevokeCertificateInputBuilder::default()
    }
}

/// A builder for [`RevokeCertificateInput`](crate::operation::revoke_certificate::RevokeCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RevokeCertificateInputBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) revocation_reason: ::std::option::Option<crate::types::RevocationReason>,
}
impl RevokeCertificateInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the public or private certificate that will be revoked. The ARN must have the following form:</p>
    /// <p><code>arn:aws:acm:region:account:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// This field is required.
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the public or private certificate that will be revoked. The ARN must have the following form:</p>
    /// <p><code>arn:aws:acm:region:account:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the public or private certificate that will be revoked. The ARN must have the following form:</p>
    /// <p><code>arn:aws:acm:region:account:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>Specifies why you revoked the certificate.</p>
    /// This field is required.
    pub fn revocation_reason(mut self, input: crate::types::RevocationReason) -> Self {
        self.revocation_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies why you revoked the certificate.</p>
    pub fn set_revocation_reason(mut self, input: ::std::option::Option<crate::types::RevocationReason>) -> Self {
        self.revocation_reason = input;
        self
    }
    /// <p>Specifies why you revoked the certificate.</p>
    pub fn get_revocation_reason(&self) -> &::std::option::Option<crate::types::RevocationReason> {
        &self.revocation_reason
    }
    /// Consumes the builder and constructs a [`RevokeCertificateInput`](crate::operation::revoke_certificate::RevokeCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::revoke_certificate::RevokeCertificateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::revoke_certificate::RevokeCertificateInput {
            certificate_arn: self.certificate_arn,
            revocation_reason: self.revocation_reason,
        })
    }
}
