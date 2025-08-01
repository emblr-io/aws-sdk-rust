// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The supported properties for a PO type data set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PoAttributes {
    /// <p>The format of the data set records.</p>
    pub format: ::std::string::String,
    /// <p>The character set encoding of the data set.</p>
    pub encoding: ::std::option::Option<::std::string::String>,
    /// <p>An array containing one or more filename extensions, allowing you to specify which files to be included as PDS member.</p>
    pub member_file_extensions: ::std::vec::Vec<::std::string::String>,
}
impl PoAttributes {
    /// <p>The format of the data set records.</p>
    pub fn format(&self) -> &str {
        use std::ops::Deref;
        self.format.deref()
    }
    /// <p>The character set encoding of the data set.</p>
    pub fn encoding(&self) -> ::std::option::Option<&str> {
        self.encoding.as_deref()
    }
    /// <p>An array containing one or more filename extensions, allowing you to specify which files to be included as PDS member.</p>
    pub fn member_file_extensions(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.member_file_extensions.deref()
    }
}
impl PoAttributes {
    /// Creates a new builder-style object to manufacture [`PoAttributes`](crate::types::PoAttributes).
    pub fn builder() -> crate::types::builders::PoAttributesBuilder {
        crate::types::builders::PoAttributesBuilder::default()
    }
}

/// A builder for [`PoAttributes`](crate::types::PoAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PoAttributesBuilder {
    pub(crate) format: ::std::option::Option<::std::string::String>,
    pub(crate) encoding: ::std::option::Option<::std::string::String>,
    pub(crate) member_file_extensions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PoAttributesBuilder {
    /// <p>The format of the data set records.</p>
    /// This field is required.
    pub fn format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format of the data set records.</p>
    pub fn set_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the data set records.</p>
    pub fn get_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.format
    }
    /// <p>The character set encoding of the data set.</p>
    pub fn encoding(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encoding = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The character set encoding of the data set.</p>
    pub fn set_encoding(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encoding = input;
        self
    }
    /// <p>The character set encoding of the data set.</p>
    pub fn get_encoding(&self) -> &::std::option::Option<::std::string::String> {
        &self.encoding
    }
    /// Appends an item to `member_file_extensions`.
    ///
    /// To override the contents of this collection use [`set_member_file_extensions`](Self::set_member_file_extensions).
    ///
    /// <p>An array containing one or more filename extensions, allowing you to specify which files to be included as PDS member.</p>
    pub fn member_file_extensions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.member_file_extensions.unwrap_or_default();
        v.push(input.into());
        self.member_file_extensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array containing one or more filename extensions, allowing you to specify which files to be included as PDS member.</p>
    pub fn set_member_file_extensions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.member_file_extensions = input;
        self
    }
    /// <p>An array containing one or more filename extensions, allowing you to specify which files to be included as PDS member.</p>
    pub fn get_member_file_extensions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.member_file_extensions
    }
    /// Consumes the builder and constructs a [`PoAttributes`](crate::types::PoAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`format`](crate::types::builders::PoAttributesBuilder::format)
    /// - [`member_file_extensions`](crate::types::builders::PoAttributesBuilder::member_file_extensions)
    pub fn build(self) -> ::std::result::Result<crate::types::PoAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PoAttributes {
            format: self.format.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "format",
                    "format was not specified but it is required when building PoAttributes",
                )
            })?,
            encoding: self.encoding,
            member_file_extensions: self.member_file_extensions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "member_file_extensions",
                    "member_file_extensions was not specified but it is required when building PoAttributes",
                )
            })?,
        })
    }
}
