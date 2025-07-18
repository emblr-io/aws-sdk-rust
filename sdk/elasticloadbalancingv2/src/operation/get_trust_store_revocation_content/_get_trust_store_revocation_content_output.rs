// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTrustStoreRevocationContentOutput {
    /// <p>The revocation files Amazon S3 URI.</p>
    pub location: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetTrustStoreRevocationContentOutput {
    /// <p>The revocation files Amazon S3 URI.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetTrustStoreRevocationContentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTrustStoreRevocationContentOutput {
    /// Creates a new builder-style object to manufacture [`GetTrustStoreRevocationContentOutput`](crate::operation::get_trust_store_revocation_content::GetTrustStoreRevocationContentOutput).
    pub fn builder() -> crate::operation::get_trust_store_revocation_content::builders::GetTrustStoreRevocationContentOutputBuilder {
        crate::operation::get_trust_store_revocation_content::builders::GetTrustStoreRevocationContentOutputBuilder::default()
    }
}

/// A builder for [`GetTrustStoreRevocationContentOutput`](crate::operation::get_trust_store_revocation_content::GetTrustStoreRevocationContentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTrustStoreRevocationContentOutputBuilder {
    pub(crate) location: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetTrustStoreRevocationContentOutputBuilder {
    /// <p>The revocation files Amazon S3 URI.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revocation files Amazon S3 URI.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The revocation files Amazon S3 URI.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTrustStoreRevocationContentOutput`](crate::operation::get_trust_store_revocation_content::GetTrustStoreRevocationContentOutput).
    pub fn build(self) -> crate::operation::get_trust_store_revocation_content::GetTrustStoreRevocationContentOutput {
        crate::operation::get_trust_store_revocation_content::GetTrustStoreRevocationContentOutput {
            location: self.location,
            _request_id: self._request_id,
        }
    }
}
