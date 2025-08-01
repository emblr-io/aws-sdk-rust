// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details related to the resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceDetails {
    /// <p>The value of the tag.</p>
    pub tag_value: ::std::option::Option<::std::string::String>,
}
impl ResourceDetails {
    /// <p>The value of the tag.</p>
    pub fn tag_value(&self) -> ::std::option::Option<&str> {
        self.tag_value.as_deref()
    }
}
impl ResourceDetails {
    /// Creates a new builder-style object to manufacture [`ResourceDetails`](crate::types::ResourceDetails).
    pub fn builder() -> crate::types::builders::ResourceDetailsBuilder {
        crate::types::builders::ResourceDetailsBuilder::default()
    }
}

/// A builder for [`ResourceDetails`](crate::types::ResourceDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceDetailsBuilder {
    pub(crate) tag_value: ::std::option::Option<::std::string::String>,
}
impl ResourceDetailsBuilder {
    /// <p>The value of the tag.</p>
    pub fn tag_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tag_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the tag.</p>
    pub fn set_tag_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tag_value = input;
        self
    }
    /// <p>The value of the tag.</p>
    pub fn get_tag_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.tag_value
    }
    /// Consumes the builder and constructs a [`ResourceDetails`](crate::types::ResourceDetails).
    pub fn build(self) -> crate::types::ResourceDetails {
        crate::types::ResourceDetails { tag_value: self.tag_value }
    }
}
