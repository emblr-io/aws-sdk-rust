// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output from the ListOutgoingCertificates operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOutgoingCertificatesOutput {
    /// <p>The certificates that are being transferred but not yet accepted.</p>
    pub outgoing_certificates: ::std::option::Option<::std::vec::Vec<crate::types::OutgoingCertificate>>,
    /// <p>The marker for the next set of results.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListOutgoingCertificatesOutput {
    /// <p>The certificates that are being transferred but not yet accepted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.outgoing_certificates.is_none()`.
    pub fn outgoing_certificates(&self) -> &[crate::types::OutgoingCertificate] {
        self.outgoing_certificates.as_deref().unwrap_or_default()
    }
    /// <p>The marker for the next set of results.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListOutgoingCertificatesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListOutgoingCertificatesOutput {
    /// Creates a new builder-style object to manufacture [`ListOutgoingCertificatesOutput`](crate::operation::list_outgoing_certificates::ListOutgoingCertificatesOutput).
    pub fn builder() -> crate::operation::list_outgoing_certificates::builders::ListOutgoingCertificatesOutputBuilder {
        crate::operation::list_outgoing_certificates::builders::ListOutgoingCertificatesOutputBuilder::default()
    }
}

/// A builder for [`ListOutgoingCertificatesOutput`](crate::operation::list_outgoing_certificates::ListOutgoingCertificatesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOutgoingCertificatesOutputBuilder {
    pub(crate) outgoing_certificates: ::std::option::Option<::std::vec::Vec<crate::types::OutgoingCertificate>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListOutgoingCertificatesOutputBuilder {
    /// Appends an item to `outgoing_certificates`.
    ///
    /// To override the contents of this collection use [`set_outgoing_certificates`](Self::set_outgoing_certificates).
    ///
    /// <p>The certificates that are being transferred but not yet accepted.</p>
    pub fn outgoing_certificates(mut self, input: crate::types::OutgoingCertificate) -> Self {
        let mut v = self.outgoing_certificates.unwrap_or_default();
        v.push(input);
        self.outgoing_certificates = ::std::option::Option::Some(v);
        self
    }
    /// <p>The certificates that are being transferred but not yet accepted.</p>
    pub fn set_outgoing_certificates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OutgoingCertificate>>) -> Self {
        self.outgoing_certificates = input;
        self
    }
    /// <p>The certificates that are being transferred but not yet accepted.</p>
    pub fn get_outgoing_certificates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OutgoingCertificate>> {
        &self.outgoing_certificates
    }
    /// <p>The marker for the next set of results.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker for the next set of results.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>The marker for the next set of results.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListOutgoingCertificatesOutput`](crate::operation::list_outgoing_certificates::ListOutgoingCertificatesOutput).
    pub fn build(self) -> crate::operation::list_outgoing_certificates::ListOutgoingCertificatesOutput {
        crate::operation::list_outgoing_certificates::ListOutgoingCertificatesOutput {
            outgoing_certificates: self.outgoing_certificates,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        }
    }
}
