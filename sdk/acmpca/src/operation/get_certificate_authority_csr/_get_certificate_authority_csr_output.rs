// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCertificateAuthorityCsrOutput {
    /// <p>The base64 PEM-encoded certificate signing request (CSR) for your private CA certificate.</p>
    pub csr: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCertificateAuthorityCsrOutput {
    /// <p>The base64 PEM-encoded certificate signing request (CSR) for your private CA certificate.</p>
    pub fn csr(&self) -> ::std::option::Option<&str> {
        self.csr.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetCertificateAuthorityCsrOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCertificateAuthorityCsrOutput {
    /// Creates a new builder-style object to manufacture [`GetCertificateAuthorityCsrOutput`](crate::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput).
    pub fn builder() -> crate::operation::get_certificate_authority_csr::builders::GetCertificateAuthorityCsrOutputBuilder {
        crate::operation::get_certificate_authority_csr::builders::GetCertificateAuthorityCsrOutputBuilder::default()
    }
}

/// A builder for [`GetCertificateAuthorityCsrOutput`](crate::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCertificateAuthorityCsrOutputBuilder {
    pub(crate) csr: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCertificateAuthorityCsrOutputBuilder {
    /// <p>The base64 PEM-encoded certificate signing request (CSR) for your private CA certificate.</p>
    pub fn csr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.csr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The base64 PEM-encoded certificate signing request (CSR) for your private CA certificate.</p>
    pub fn set_csr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.csr = input;
        self
    }
    /// <p>The base64 PEM-encoded certificate signing request (CSR) for your private CA certificate.</p>
    pub fn get_csr(&self) -> &::std::option::Option<::std::string::String> {
        &self.csr
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCertificateAuthorityCsrOutput`](crate::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput).
    pub fn build(self) -> crate::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput {
        crate::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput {
            csr: self.csr,
            _request_id: self._request_id,
        }
    }
}
