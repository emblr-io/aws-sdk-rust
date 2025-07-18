// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCertificateOutput {
    /// <p>Metadata about an ACM certificate.</p>
    pub certificate: ::std::option::Option<crate::types::CertificateDetail>,
    _request_id: Option<String>,
}
impl DescribeCertificateOutput {
    /// <p>Metadata about an ACM certificate.</p>
    pub fn certificate(&self) -> ::std::option::Option<&crate::types::CertificateDetail> {
        self.certificate.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCertificateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCertificateOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCertificateOutput`](crate::operation::describe_certificate::DescribeCertificateOutput).
    pub fn builder() -> crate::operation::describe_certificate::builders::DescribeCertificateOutputBuilder {
        crate::operation::describe_certificate::builders::DescribeCertificateOutputBuilder::default()
    }
}

/// A builder for [`DescribeCertificateOutput`](crate::operation::describe_certificate::DescribeCertificateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCertificateOutputBuilder {
    pub(crate) certificate: ::std::option::Option<crate::types::CertificateDetail>,
    _request_id: Option<String>,
}
impl DescribeCertificateOutputBuilder {
    /// <p>Metadata about an ACM certificate.</p>
    pub fn certificate(mut self, input: crate::types::CertificateDetail) -> Self {
        self.certificate = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata about an ACM certificate.</p>
    pub fn set_certificate(mut self, input: ::std::option::Option<crate::types::CertificateDetail>) -> Self {
        self.certificate = input;
        self
    }
    /// <p>Metadata about an ACM certificate.</p>
    pub fn get_certificate(&self) -> &::std::option::Option<crate::types::CertificateDetail> {
        &self.certificate
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCertificateOutput`](crate::operation::describe_certificate::DescribeCertificateOutput).
    pub fn build(self) -> crate::operation::describe_certificate::DescribeCertificateOutput {
        crate::operation::describe_certificate::DescribeCertificateOutput {
            certificate: self.certificate,
            _request_id: self._request_id,
        }
    }
}
