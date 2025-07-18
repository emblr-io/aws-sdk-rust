// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRepositoryEndpointOutput {
    /// <p>A string that specifies the URL of the returned endpoint.</p>
    pub repository_endpoint: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRepositoryEndpointOutput {
    /// <p>A string that specifies the URL of the returned endpoint.</p>
    pub fn repository_endpoint(&self) -> ::std::option::Option<&str> {
        self.repository_endpoint.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetRepositoryEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRepositoryEndpointOutput {
    /// Creates a new builder-style object to manufacture [`GetRepositoryEndpointOutput`](crate::operation::get_repository_endpoint::GetRepositoryEndpointOutput).
    pub fn builder() -> crate::operation::get_repository_endpoint::builders::GetRepositoryEndpointOutputBuilder {
        crate::operation::get_repository_endpoint::builders::GetRepositoryEndpointOutputBuilder::default()
    }
}

/// A builder for [`GetRepositoryEndpointOutput`](crate::operation::get_repository_endpoint::GetRepositoryEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRepositoryEndpointOutputBuilder {
    pub(crate) repository_endpoint: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRepositoryEndpointOutputBuilder {
    /// <p>A string that specifies the URL of the returned endpoint.</p>
    pub fn repository_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that specifies the URL of the returned endpoint.</p>
    pub fn set_repository_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_endpoint = input;
        self
    }
    /// <p>A string that specifies the URL of the returned endpoint.</p>
    pub fn get_repository_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_endpoint
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRepositoryEndpointOutput`](crate::operation::get_repository_endpoint::GetRepositoryEndpointOutput).
    pub fn build(self) -> crate::operation::get_repository_endpoint::GetRepositoryEndpointOutput {
        crate::operation::get_repository_endpoint::GetRepositoryEndpointOutput {
            repository_endpoint: self.repository_endpoint,
            _request_id: self._request_id,
        }
    }
}
