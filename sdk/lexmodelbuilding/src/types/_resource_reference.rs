// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the resource that refers to the resource that you are attempting to delete. This object is returned as part of the <code>ResourceInUseException</code> exception.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceReference {
    /// <p>The name of the resource that is using the resource that you are trying to delete.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the resource that is using the resource that you are trying to delete.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl ResourceReference {
    /// <p>The name of the resource that is using the resource that you are trying to delete.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of the resource that is using the resource that you are trying to delete.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl ResourceReference {
    /// Creates a new builder-style object to manufacture [`ResourceReference`](crate::types::ResourceReference).
    pub fn builder() -> crate::types::builders::ResourceReferenceBuilder {
        crate::types::builders::ResourceReferenceBuilder::default()
    }
}

/// A builder for [`ResourceReference`](crate::types::ResourceReference).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceReferenceBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl ResourceReferenceBuilder {
    /// <p>The name of the resource that is using the resource that you are trying to delete.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource that is using the resource that you are trying to delete.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource that is using the resource that you are trying to delete.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of the resource that is using the resource that you are trying to delete.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the resource that is using the resource that you are trying to delete.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the resource that is using the resource that you are trying to delete.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`ResourceReference`](crate::types::ResourceReference).
    pub fn build(self) -> crate::types::ResourceReference {
        crate::types::ResourceReference {
            name: self.name,
            version: self.version,
        }
    }
}
