// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The source of the static file that contains the image.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SheetImageStaticFileSource {
    /// <p>The ID of the static file that contains the image.</p>
    pub static_file_id: ::std::string::String,
}
impl SheetImageStaticFileSource {
    /// <p>The ID of the static file that contains the image.</p>
    pub fn static_file_id(&self) -> &str {
        use std::ops::Deref;
        self.static_file_id.deref()
    }
}
impl SheetImageStaticFileSource {
    /// Creates a new builder-style object to manufacture [`SheetImageStaticFileSource`](crate::types::SheetImageStaticFileSource).
    pub fn builder() -> crate::types::builders::SheetImageStaticFileSourceBuilder {
        crate::types::builders::SheetImageStaticFileSourceBuilder::default()
    }
}

/// A builder for [`SheetImageStaticFileSource`](crate::types::SheetImageStaticFileSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SheetImageStaticFileSourceBuilder {
    pub(crate) static_file_id: ::std::option::Option<::std::string::String>,
}
impl SheetImageStaticFileSourceBuilder {
    /// <p>The ID of the static file that contains the image.</p>
    /// This field is required.
    pub fn static_file_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.static_file_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the static file that contains the image.</p>
    pub fn set_static_file_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.static_file_id = input;
        self
    }
    /// <p>The ID of the static file that contains the image.</p>
    pub fn get_static_file_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.static_file_id
    }
    /// Consumes the builder and constructs a [`SheetImageStaticFileSource`](crate::types::SheetImageStaticFileSource).
    /// This method will fail if any of the following fields are not set:
    /// - [`static_file_id`](crate::types::builders::SheetImageStaticFileSourceBuilder::static_file_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SheetImageStaticFileSource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SheetImageStaticFileSource {
            static_file_id: self.static_file_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "static_file_id",
                    "static_file_id was not specified but it is required when building SheetImageStaticFileSource",
                )
            })?,
        })
    }
}
