// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApiKeyOutput {
    /// <p>The API key.</p>
    pub api_key: ::std::option::Option<crate::types::ApiKey>,
    _request_id: Option<String>,
}
impl CreateApiKeyOutput {
    /// <p>The API key.</p>
    pub fn api_key(&self) -> ::std::option::Option<&crate::types::ApiKey> {
        self.api_key.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateApiKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateApiKeyOutput {
    /// Creates a new builder-style object to manufacture [`CreateApiKeyOutput`](crate::operation::create_api_key::CreateApiKeyOutput).
    pub fn builder() -> crate::operation::create_api_key::builders::CreateApiKeyOutputBuilder {
        crate::operation::create_api_key::builders::CreateApiKeyOutputBuilder::default()
    }
}

/// A builder for [`CreateApiKeyOutput`](crate::operation::create_api_key::CreateApiKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApiKeyOutputBuilder {
    pub(crate) api_key: ::std::option::Option<crate::types::ApiKey>,
    _request_id: Option<String>,
}
impl CreateApiKeyOutputBuilder {
    /// <p>The API key.</p>
    pub fn api_key(mut self, input: crate::types::ApiKey) -> Self {
        self.api_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The API key.</p>
    pub fn set_api_key(mut self, input: ::std::option::Option<crate::types::ApiKey>) -> Self {
        self.api_key = input;
        self
    }
    /// <p>The API key.</p>
    pub fn get_api_key(&self) -> &::std::option::Option<crate::types::ApiKey> {
        &self.api_key
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateApiKeyOutput`](crate::operation::create_api_key::CreateApiKeyOutput).
    pub fn build(self) -> crate::operation::create_api_key::CreateApiKeyOutput {
        crate::operation::create_api_key::CreateApiKeyOutput {
            api_key: self.api_key,
            _request_id: self._request_id,
        }
    }
}
