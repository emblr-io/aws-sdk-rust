// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Amazon Web Services Region in which Amazon Web Services Control Tower expects to find the control deployed.</p>
/// <p>The expected Regions are based on the Regions that are governed by the landing zone. In certain cases, a control is not actually enabled in the Region as expected, such as during drift, or <a href="https://docs.aws.amazon.com/controltower/latest/userguide/region-how.html#mixed-governance">mixed governance</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Region {
    /// <p>The Amazon Web Services Region name.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl Region {
    /// <p>The Amazon Web Services Region name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl Region {
    /// Creates a new builder-style object to manufacture [`Region`](crate::types::Region).
    pub fn builder() -> crate::types::builders::RegionBuilder {
        crate::types::builders::RegionBuilder::default()
    }
}

/// A builder for [`Region`](crate::types::Region).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl RegionBuilder {
    /// <p>The Amazon Web Services Region name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The Amazon Web Services Region name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`Region`](crate::types::Region).
    pub fn build(self) -> crate::types::Region {
        crate::types::Region { name: self.name }
    }
}
