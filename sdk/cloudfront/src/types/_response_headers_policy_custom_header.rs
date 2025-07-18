// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An HTTP response header name and its value. CloudFront includes this header in HTTP responses that it sends for requests that match a cache behavior that's associated with this response headers policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResponseHeadersPolicyCustomHeader {
    /// <p>The HTTP response header name.</p>
    pub header: ::std::string::String,
    /// <p>The value for the HTTP response header.</p>
    pub value: ::std::string::String,
    /// <p>A Boolean that determines whether CloudFront overrides a response header with the same name received from the origin with the header specified here.</p>
    pub r#override: bool,
}
impl ResponseHeadersPolicyCustomHeader {
    /// <p>The HTTP response header name.</p>
    pub fn header(&self) -> &str {
        use std::ops::Deref;
        self.header.deref()
    }
    /// <p>The value for the HTTP response header.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>A Boolean that determines whether CloudFront overrides a response header with the same name received from the origin with the header specified here.</p>
    pub fn r#override(&self) -> bool {
        self.r#override
    }
}
impl ResponseHeadersPolicyCustomHeader {
    /// Creates a new builder-style object to manufacture [`ResponseHeadersPolicyCustomHeader`](crate::types::ResponseHeadersPolicyCustomHeader).
    pub fn builder() -> crate::types::builders::ResponseHeadersPolicyCustomHeaderBuilder {
        crate::types::builders::ResponseHeadersPolicyCustomHeaderBuilder::default()
    }
}

/// A builder for [`ResponseHeadersPolicyCustomHeader`](crate::types::ResponseHeadersPolicyCustomHeader).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResponseHeadersPolicyCustomHeaderBuilder {
    pub(crate) header: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) r#override: ::std::option::Option<bool>,
}
impl ResponseHeadersPolicyCustomHeaderBuilder {
    /// <p>The HTTP response header name.</p>
    /// This field is required.
    pub fn header(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.header = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP response header name.</p>
    pub fn set_header(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.header = input;
        self
    }
    /// <p>The HTTP response header name.</p>
    pub fn get_header(&self) -> &::std::option::Option<::std::string::String> {
        &self.header
    }
    /// <p>The value for the HTTP response header.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value for the HTTP response header.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value for the HTTP response header.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>A Boolean that determines whether CloudFront overrides a response header with the same name received from the origin with the header specified here.</p>
    /// This field is required.
    pub fn r#override(mut self, input: bool) -> Self {
        self.r#override = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean that determines whether CloudFront overrides a response header with the same name received from the origin with the header specified here.</p>
    pub fn set_override(mut self, input: ::std::option::Option<bool>) -> Self {
        self.r#override = input;
        self
    }
    /// <p>A Boolean that determines whether CloudFront overrides a response header with the same name received from the origin with the header specified here.</p>
    pub fn get_override(&self) -> &::std::option::Option<bool> {
        &self.r#override
    }
    /// Consumes the builder and constructs a [`ResponseHeadersPolicyCustomHeader`](crate::types::ResponseHeadersPolicyCustomHeader).
    /// This method will fail if any of the following fields are not set:
    /// - [`header`](crate::types::builders::ResponseHeadersPolicyCustomHeaderBuilder::header)
    /// - [`value`](crate::types::builders::ResponseHeadersPolicyCustomHeaderBuilder::value)
    /// - [`r#override`](crate::types::builders::ResponseHeadersPolicyCustomHeaderBuilder::override)
    pub fn build(self) -> ::std::result::Result<crate::types::ResponseHeadersPolicyCustomHeader, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResponseHeadersPolicyCustomHeader {
            header: self.header.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "header",
                    "header was not specified but it is required when building ResponseHeadersPolicyCustomHeader",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building ResponseHeadersPolicyCustomHeader",
                )
            })?,
            r#override: self.r#override.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#override",
                    "r#override was not specified but it is required when building ResponseHeadersPolicyCustomHeader",
                )
            })?,
        })
    }
}
