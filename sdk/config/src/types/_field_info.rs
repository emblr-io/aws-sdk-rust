// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the fields such as name of the field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldInfo {
    /// <p>Name of the field.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl FieldInfo {
    /// <p>Name of the field.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl FieldInfo {
    /// Creates a new builder-style object to manufacture [`FieldInfo`](crate::types::FieldInfo).
    pub fn builder() -> crate::types::builders::FieldInfoBuilder {
        crate::types::builders::FieldInfoBuilder::default()
    }
}

/// A builder for [`FieldInfo`](crate::types::FieldInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldInfoBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl FieldInfoBuilder {
    /// <p>Name of the field.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the field.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the field.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`FieldInfo`](crate::types::FieldInfo).
    pub fn build(self) -> crate::types::FieldInfo {
        crate::types::FieldInfo { name: self.name }
    }
}
