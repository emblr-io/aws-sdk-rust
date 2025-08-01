// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output of the ListCertificatesByCA operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCertificatesByCaOutput {
    /// <p>The device certificates signed by the specified CA certificate.</p>
    pub certificates: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>,
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCertificatesByCaOutput {
    /// <p>The device certificates signed by the specified CA certificate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.certificates.is_none()`.
    pub fn certificates(&self) -> &[crate::types::Certificate] {
        self.certificates.as_deref().unwrap_or_default()
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListCertificatesByCaOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCertificatesByCaOutput {
    /// Creates a new builder-style object to manufacture [`ListCertificatesByCaOutput`](crate::operation::list_certificates_by_ca::ListCertificatesByCaOutput).
    pub fn builder() -> crate::operation::list_certificates_by_ca::builders::ListCertificatesByCaOutputBuilder {
        crate::operation::list_certificates_by_ca::builders::ListCertificatesByCaOutputBuilder::default()
    }
}

/// A builder for [`ListCertificatesByCaOutput`](crate::operation::list_certificates_by_ca::ListCertificatesByCaOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCertificatesByCaOutputBuilder {
    pub(crate) certificates: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCertificatesByCaOutputBuilder {
    /// Appends an item to `certificates`.
    ///
    /// To override the contents of this collection use [`set_certificates`](Self::set_certificates).
    ///
    /// <p>The device certificates signed by the specified CA certificate.</p>
    pub fn certificates(mut self, input: crate::types::Certificate) -> Self {
        let mut v = self.certificates.unwrap_or_default();
        v.push(input);
        self.certificates = ::std::option::Option::Some(v);
        self
    }
    /// <p>The device certificates signed by the specified CA certificate.</p>
    pub fn set_certificates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Certificate>>) -> Self {
        self.certificates = input;
        self
    }
    /// <p>The device certificates signed by the specified CA certificate.</p>
    pub fn get_certificates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Certificate>> {
        &self.certificates
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
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
    /// Consumes the builder and constructs a [`ListCertificatesByCaOutput`](crate::operation::list_certificates_by_ca::ListCertificatesByCaOutput).
    pub fn build(self) -> crate::operation::list_certificates_by_ca::ListCertificatesByCaOutput {
        crate::operation::list_certificates_by_ca::ListCertificatesByCaOutput {
            certificates: self.certificates,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        }
    }
}
