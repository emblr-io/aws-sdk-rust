// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCertificateAuthorityCertificateOutput {
    /// <p>Base64-encoded certificate authority (CA) certificate.</p>
    pub certificate: ::std::option::Option<::std::string::String>,
    /// <p>Base64-encoded certificate chain that includes any intermediate certificates and chains up to root certificate that you used to sign your private CA certificate. The chain does not include your private CA certificate. If this is a root CA, the value will be null.</p>
    pub certificate_chain: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCertificateAuthorityCertificateOutput {
    /// <p>Base64-encoded certificate authority (CA) certificate.</p>
    pub fn certificate(&self) -> ::std::option::Option<&str> {
        self.certificate.as_deref()
    }
    /// <p>Base64-encoded certificate chain that includes any intermediate certificates and chains up to root certificate that you used to sign your private CA certificate. The chain does not include your private CA certificate. If this is a root CA, the value will be null.</p>
    pub fn certificate_chain(&self) -> ::std::option::Option<&str> {
        self.certificate_chain.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetCertificateAuthorityCertificateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCertificateAuthorityCertificateOutput {
    /// Creates a new builder-style object to manufacture [`GetCertificateAuthorityCertificateOutput`](crate::operation::get_certificate_authority_certificate::GetCertificateAuthorityCertificateOutput).
    pub fn builder() -> crate::operation::get_certificate_authority_certificate::builders::GetCertificateAuthorityCertificateOutputBuilder {
        crate::operation::get_certificate_authority_certificate::builders::GetCertificateAuthorityCertificateOutputBuilder::default()
    }
}

/// A builder for [`GetCertificateAuthorityCertificateOutput`](crate::operation::get_certificate_authority_certificate::GetCertificateAuthorityCertificateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCertificateAuthorityCertificateOutputBuilder {
    pub(crate) certificate: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_chain: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCertificateAuthorityCertificateOutputBuilder {
    /// <p>Base64-encoded certificate authority (CA) certificate.</p>
    pub fn certificate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Base64-encoded certificate authority (CA) certificate.</p>
    pub fn set_certificate(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate = input;
        self
    }
    /// <p>Base64-encoded certificate authority (CA) certificate.</p>
    pub fn get_certificate(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate
    }
    /// <p>Base64-encoded certificate chain that includes any intermediate certificates and chains up to root certificate that you used to sign your private CA certificate. The chain does not include your private CA certificate. If this is a root CA, the value will be null.</p>
    pub fn certificate_chain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_chain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Base64-encoded certificate chain that includes any intermediate certificates and chains up to root certificate that you used to sign your private CA certificate. The chain does not include your private CA certificate. If this is a root CA, the value will be null.</p>
    pub fn set_certificate_chain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_chain = input;
        self
    }
    /// <p>Base64-encoded certificate chain that includes any intermediate certificates and chains up to root certificate that you used to sign your private CA certificate. The chain does not include your private CA certificate. If this is a root CA, the value will be null.</p>
    pub fn get_certificate_chain(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_chain
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCertificateAuthorityCertificateOutput`](crate::operation::get_certificate_authority_certificate::GetCertificateAuthorityCertificateOutput).
    pub fn build(self) -> crate::operation::get_certificate_authority_certificate::GetCertificateAuthorityCertificateOutput {
        crate::operation::get_certificate_authority_certificate::GetCertificateAuthorityCertificateOutput {
            certificate: self.certificate,
            certificate_chain: self.certificate_chain,
            _request_id: self._request_id,
        }
    }
}
