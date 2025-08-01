// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The tag structure that contains a tag key and value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceTag {
    /// <p>The key that's associated with the tag.</p>
    pub key: ::std::string::String,
    /// <p>The value that's associated with the tag.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl ResourceTag {
    /// <p>The key that's associated with the tag.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>The value that's associated with the tag.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl ResourceTag {
    /// Creates a new builder-style object to manufacture [`ResourceTag`](crate::types::ResourceTag).
    pub fn builder() -> crate::types::builders::ResourceTagBuilder {
        crate::types::builders::ResourceTagBuilder::default()
    }
}

/// A builder for [`ResourceTag`](crate::types::ResourceTag).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceTagBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl ResourceTagBuilder {
    /// <p>The key that's associated with the tag.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key that's associated with the tag.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key that's associated with the tag.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The value that's associated with the tag.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value that's associated with the tag.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value that's associated with the tag.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ResourceTag`](crate::types::ResourceTag).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::ResourceTagBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::ResourceTag, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResourceTag {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building ResourceTag",
                )
            })?,
            value: self.value,
        })
    }
}
