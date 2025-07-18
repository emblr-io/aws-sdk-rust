// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A video block.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoBlock {
    /// <p>The block's format.</p>
    pub format: crate::types::VideoFormat,
    /// <p>The block's source.</p>
    pub source: ::std::option::Option<crate::types::VideoSource>,
}
impl VideoBlock {
    /// <p>The block's format.</p>
    pub fn format(&self) -> &crate::types::VideoFormat {
        &self.format
    }
    /// <p>The block's source.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::VideoSource> {
        self.source.as_ref()
    }
}
impl VideoBlock {
    /// Creates a new builder-style object to manufacture [`VideoBlock`](crate::types::VideoBlock).
    pub fn builder() -> crate::types::builders::VideoBlockBuilder {
        crate::types::builders::VideoBlockBuilder::default()
    }
}

/// A builder for [`VideoBlock`](crate::types::VideoBlock).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoBlockBuilder {
    pub(crate) format: ::std::option::Option<crate::types::VideoFormat>,
    pub(crate) source: ::std::option::Option<crate::types::VideoSource>,
}
impl VideoBlockBuilder {
    /// <p>The block's format.</p>
    /// This field is required.
    pub fn format(mut self, input: crate::types::VideoFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The block's format.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::VideoFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>The block's format.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::VideoFormat> {
        &self.format
    }
    /// <p>The block's source.</p>
    /// This field is required.
    pub fn source(mut self, input: crate::types::VideoSource) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The block's source.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::VideoSource>) -> Self {
        self.source = input;
        self
    }
    /// <p>The block's source.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::VideoSource> {
        &self.source
    }
    /// Consumes the builder and constructs a [`VideoBlock`](crate::types::VideoBlock).
    /// This method will fail if any of the following fields are not set:
    /// - [`format`](crate::types::builders::VideoBlockBuilder::format)
    pub fn build(self) -> ::std::result::Result<crate::types::VideoBlock, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VideoBlock {
            format: self.format.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "format",
                    "format was not specified but it is required when building VideoBlock",
                )
            })?,
            source: self.source,
        })
    }
}
