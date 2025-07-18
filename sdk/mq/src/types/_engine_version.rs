// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Id of the engine version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EngineVersion {
    /// <p>Id for the version.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl EngineVersion {
    /// <p>Id for the version.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl EngineVersion {
    /// Creates a new builder-style object to manufacture [`EngineVersion`](crate::types::EngineVersion).
    pub fn builder() -> crate::types::builders::EngineVersionBuilder {
        crate::types::builders::EngineVersionBuilder::default()
    }
}

/// A builder for [`EngineVersion`](crate::types::EngineVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EngineVersionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl EngineVersionBuilder {
    /// <p>Id for the version.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Id for the version.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Id for the version.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`EngineVersion`](crate::types::EngineVersion).
    pub fn build(self) -> crate::types::EngineVersion {
        crate::types::EngineVersion { name: self.name }
    }
}
