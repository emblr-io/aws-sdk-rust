// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCertificateAuthorityOutput {
    /// <p>If successful, the Amazon Resource Name (ARN) of the certificate authority (CA). This is of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code>.</p>
    pub certificate_authority_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCertificateAuthorityOutput {
    /// <p>If successful, the Amazon Resource Name (ARN) of the certificate authority (CA). This is of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code>.</p>
    pub fn certificate_authority_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_authority_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCertificateAuthorityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCertificateAuthorityOutput {
    /// Creates a new builder-style object to manufacture [`CreateCertificateAuthorityOutput`](crate::operation::create_certificate_authority::CreateCertificateAuthorityOutput).
    pub fn builder() -> crate::operation::create_certificate_authority::builders::CreateCertificateAuthorityOutputBuilder {
        crate::operation::create_certificate_authority::builders::CreateCertificateAuthorityOutputBuilder::default()
    }
}

/// A builder for [`CreateCertificateAuthorityOutput`](crate::operation::create_certificate_authority::CreateCertificateAuthorityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCertificateAuthorityOutputBuilder {
    pub(crate) certificate_authority_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCertificateAuthorityOutputBuilder {
    /// <p>If successful, the Amazon Resource Name (ARN) of the certificate authority (CA). This is of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code>.</p>
    pub fn certificate_authority_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_authority_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If successful, the Amazon Resource Name (ARN) of the certificate authority (CA). This is of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code>.</p>
    pub fn set_certificate_authority_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_authority_arn = input;
        self
    }
    /// <p>If successful, the Amazon Resource Name (ARN) of the certificate authority (CA). This is of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code>.</p>
    pub fn get_certificate_authority_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_authority_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCertificateAuthorityOutput`](crate::operation::create_certificate_authority::CreateCertificateAuthorityOutput).
    pub fn build(self) -> crate::operation::create_certificate_authority::CreateCertificateAuthorityOutput {
        crate::operation::create_certificate_authority::CreateCertificateAuthorityOutput {
            certificate_authority_arn: self.certificate_authority_arn,
            _request_id: self._request_id,
        }
    }
}
