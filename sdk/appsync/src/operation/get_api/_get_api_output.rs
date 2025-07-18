// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApiOutput {
    /// <p>The <code>Api</code> object.</p>
    pub api: ::std::option::Option<crate::types::Api>,
    _request_id: Option<String>,
}
impl GetApiOutput {
    /// <p>The <code>Api</code> object.</p>
    pub fn api(&self) -> ::std::option::Option<&crate::types::Api> {
        self.api.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetApiOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetApiOutput {
    /// Creates a new builder-style object to manufacture [`GetApiOutput`](crate::operation::get_api::GetApiOutput).
    pub fn builder() -> crate::operation::get_api::builders::GetApiOutputBuilder {
        crate::operation::get_api::builders::GetApiOutputBuilder::default()
    }
}

/// A builder for [`GetApiOutput`](crate::operation::get_api::GetApiOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApiOutputBuilder {
    pub(crate) api: ::std::option::Option<crate::types::Api>,
    _request_id: Option<String>,
}
impl GetApiOutputBuilder {
    /// <p>The <code>Api</code> object.</p>
    pub fn api(mut self, input: crate::types::Api) -> Self {
        self.api = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>Api</code> object.</p>
    pub fn set_api(mut self, input: ::std::option::Option<crate::types::Api>) -> Self {
        self.api = input;
        self
    }
    /// <p>The <code>Api</code> object.</p>
    pub fn get_api(&self) -> &::std::option::Option<crate::types::Api> {
        &self.api
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetApiOutput`](crate::operation::get_api::GetApiOutput).
    pub fn build(self) -> crate::operation::get_api::GetApiOutput {
        crate::operation::get_api::GetApiOutput {
            api: self.api,
            _request_id: self._request_id,
        }
    }
}
