// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure that contains the URL to download the static file from.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StaticFileUrlSourceOptions {
    /// <p>The URL to download the static file from.</p>
    pub url: ::std::string::String,
}
impl StaticFileUrlSourceOptions {
    /// <p>The URL to download the static file from.</p>
    pub fn url(&self) -> &str {
        use std::ops::Deref;
        self.url.deref()
    }
}
impl StaticFileUrlSourceOptions {
    /// Creates a new builder-style object to manufacture [`StaticFileUrlSourceOptions`](crate::types::StaticFileUrlSourceOptions).
    pub fn builder() -> crate::types::builders::StaticFileUrlSourceOptionsBuilder {
        crate::types::builders::StaticFileUrlSourceOptionsBuilder::default()
    }
}

/// A builder for [`StaticFileUrlSourceOptions`](crate::types::StaticFileUrlSourceOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StaticFileUrlSourceOptionsBuilder {
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl StaticFileUrlSourceOptionsBuilder {
    /// <p>The URL to download the static file from.</p>
    /// This field is required.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL to download the static file from.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL to download the static file from.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`StaticFileUrlSourceOptions`](crate::types::StaticFileUrlSourceOptions).
    /// This method will fail if any of the following fields are not set:
    /// - [`url`](crate::types::builders::StaticFileUrlSourceOptionsBuilder::url)
    pub fn build(self) -> ::std::result::Result<crate::types::StaticFileUrlSourceOptions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StaticFileUrlSourceOptions {
            url: self.url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "url",
                    "url was not specified but it is required when building StaticFileUrlSourceOptions",
                )
            })?,
        })
    }
}
