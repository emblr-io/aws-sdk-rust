// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSdkOutput {
    /// <p>The content-type header value in the HTTP response.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>The content-disposition header value in the HTTP response.</p>
    pub content_disposition: ::std::option::Option<::std::string::String>,
    /// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
    pub body: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GetSdkOutput {
    /// <p>The content-type header value in the HTTP response.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>The content-disposition header value in the HTTP response.</p>
    pub fn content_disposition(&self) -> ::std::option::Option<&str> {
        self.content_disposition.as_deref()
    }
    /// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
    pub fn body(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.body.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSdkOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSdkOutput {
    /// Creates a new builder-style object to manufacture [`GetSdkOutput`](crate::operation::get_sdk::GetSdkOutput).
    pub fn builder() -> crate::operation::get_sdk::builders::GetSdkOutputBuilder {
        crate::operation::get_sdk::builders::GetSdkOutputBuilder::default()
    }
}

/// A builder for [`GetSdkOutput`](crate::operation::get_sdk::GetSdkOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSdkOutputBuilder {
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) content_disposition: ::std::option::Option<::std::string::String>,
    pub(crate) body: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GetSdkOutputBuilder {
    /// <p>The content-type header value in the HTTP response.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content-type header value in the HTTP response.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The content-type header value in the HTTP response.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>The content-disposition header value in the HTTP response.</p>
    pub fn content_disposition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_disposition = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content-disposition header value in the HTTP response.</p>
    pub fn set_content_disposition(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_disposition = input;
        self
    }
    /// <p>The content-disposition header value in the HTTP response.</p>
    pub fn get_content_disposition(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_disposition
    }
    /// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
    pub fn body(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.body = ::std::option::Option::Some(input);
        self
    }
    /// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.body = input;
        self
    }
    /// <p>The binary blob response to GetSdk, which contains the generated SDK.</p>
    pub fn get_body(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.body
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSdkOutput`](crate::operation::get_sdk::GetSdkOutput).
    pub fn build(self) -> crate::operation::get_sdk::GetSdkOutput {
        crate::operation::get_sdk::GetSdkOutput {
            content_type: self.content_type,
            content_disposition: self.content_disposition,
            body: self.body,
            _request_id: self._request_id,
        }
    }
}
