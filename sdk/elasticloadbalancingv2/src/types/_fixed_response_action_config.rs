// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an action that returns a custom HTTP response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FixedResponseActionConfig {
    /// <p>The message.</p>
    pub message_body: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP response code (2XX, 4XX, or 5XX).</p>
    pub status_code: ::std::option::Option<::std::string::String>,
    /// <p>The content type.</p>
    /// <p>Valid Values: text/plain | text/css | text/html | application/javascript | application/json</p>
    pub content_type: ::std::option::Option<::std::string::String>,
}
impl FixedResponseActionConfig {
    /// <p>The message.</p>
    pub fn message_body(&self) -> ::std::option::Option<&str> {
        self.message_body.as_deref()
    }
    /// <p>The HTTP response code (2XX, 4XX, or 5XX).</p>
    pub fn status_code(&self) -> ::std::option::Option<&str> {
        self.status_code.as_deref()
    }
    /// <p>The content type.</p>
    /// <p>Valid Values: text/plain | text/css | text/html | application/javascript | application/json</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
}
impl FixedResponseActionConfig {
    /// Creates a new builder-style object to manufacture [`FixedResponseActionConfig`](crate::types::FixedResponseActionConfig).
    pub fn builder() -> crate::types::builders::FixedResponseActionConfigBuilder {
        crate::types::builders::FixedResponseActionConfigBuilder::default()
    }
}

/// A builder for [`FixedResponseActionConfig`](crate::types::FixedResponseActionConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FixedResponseActionConfigBuilder {
    pub(crate) message_body: ::std::option::Option<::std::string::String>,
    pub(crate) status_code: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
}
impl FixedResponseActionConfigBuilder {
    /// <p>The message.</p>
    pub fn message_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message.</p>
    pub fn set_message_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_body = input;
        self
    }
    /// <p>The message.</p>
    pub fn get_message_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_body
    }
    /// <p>The HTTP response code (2XX, 4XX, or 5XX).</p>
    /// This field is required.
    pub fn status_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP response code (2XX, 4XX, or 5XX).</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The HTTP response code (2XX, 4XX, or 5XX).</p>
    pub fn get_status_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_code
    }
    /// <p>The content type.</p>
    /// <p>Valid Values: text/plain | text/css | text/html | application/javascript | application/json</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content type.</p>
    /// <p>Valid Values: text/plain | text/css | text/html | application/javascript | application/json</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The content type.</p>
    /// <p>Valid Values: text/plain | text/css | text/html | application/javascript | application/json</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// Consumes the builder and constructs a [`FixedResponseActionConfig`](crate::types::FixedResponseActionConfig).
    pub fn build(self) -> crate::types::FixedResponseActionConfig {
        crate::types::FixedResponseActionConfig {
            message_body: self.message_body,
            status_code: self.status_code,
            content_type: self.content_type,
        }
    }
}
