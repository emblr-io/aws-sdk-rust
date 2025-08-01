// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddListenerCertificatesOutput {
    /// <p>Information about the certificates in the certificate list.</p>
    pub certificates: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>,
    _request_id: Option<String>,
}
impl AddListenerCertificatesOutput {
    /// <p>Information about the certificates in the certificate list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.certificates.is_none()`.
    pub fn certificates(&self) -> &[crate::types::Certificate] {
        self.certificates.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for AddListenerCertificatesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AddListenerCertificatesOutput {
    /// Creates a new builder-style object to manufacture [`AddListenerCertificatesOutput`](crate::operation::add_listener_certificates::AddListenerCertificatesOutput).
    pub fn builder() -> crate::operation::add_listener_certificates::builders::AddListenerCertificatesOutputBuilder {
        crate::operation::add_listener_certificates::builders::AddListenerCertificatesOutputBuilder::default()
    }
}

/// A builder for [`AddListenerCertificatesOutput`](crate::operation::add_listener_certificates::AddListenerCertificatesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddListenerCertificatesOutputBuilder {
    pub(crate) certificates: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>,
    _request_id: Option<String>,
}
impl AddListenerCertificatesOutputBuilder {
    /// Appends an item to `certificates`.
    ///
    /// To override the contents of this collection use [`set_certificates`](Self::set_certificates).
    ///
    /// <p>Information about the certificates in the certificate list.</p>
    pub fn certificates(mut self, input: crate::types::Certificate) -> Self {
        let mut v = self.certificates.unwrap_or_default();
        v.push(input);
        self.certificates = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the certificates in the certificate list.</p>
    pub fn set_certificates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>) -> Self {
        self.certificates = input;
        self
    }
    /// <p>Information about the certificates in the certificate list.</p>
    pub fn get_certificates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Certificate>> {
        &self.certificates
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AddListenerCertificatesOutput`](crate::operation::add_listener_certificates::AddListenerCertificatesOutput).
    pub fn build(self) -> crate::operation::add_listener_certificates::AddListenerCertificatesOutput {
        crate::operation::add_listener_certificates::AddListenerCertificatesOutput {
            certificates: self.certificates,
            _request_id: self._request_id,
        }
    }
}
