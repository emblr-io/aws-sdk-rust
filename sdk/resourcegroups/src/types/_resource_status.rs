// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that identifies the current group membership status for a resource. Adding a resource to a resource group is performed asynchronously as a background task. A <code>PENDING</code> status indicates, for this resource, that the process isn't completed yet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceStatus {
    /// <p>The current status.</p>
    pub name: ::std::option::Option<crate::types::ResourceStatusValue>,
}
impl ResourceStatus {
    /// <p>The current status.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::ResourceStatusValue> {
        self.name.as_ref()
    }
}
impl ResourceStatus {
    /// Creates a new builder-style object to manufacture [`ResourceStatus`](crate::types::ResourceStatus).
    pub fn builder() -> crate::types::builders::ResourceStatusBuilder {
        crate::types::builders::ResourceStatusBuilder::default()
    }
}

/// A builder for [`ResourceStatus`](crate::types::ResourceStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceStatusBuilder {
    pub(crate) name: ::std::option::Option<crate::types::ResourceStatusValue>,
}
impl ResourceStatusBuilder {
    /// <p>The current status.</p>
    pub fn name(mut self, input: crate::types::ResourceStatusValue) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::ResourceStatusValue>) -> Self {
        self.name = input;
        self
    }
    /// <p>The current status.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::ResourceStatusValue> {
        &self.name
    }
    /// Consumes the builder and constructs a [`ResourceStatus`](crate::types::ResourceStatus).
    pub fn build(self) -> crate::types::ResourceStatus {
        crate::types::ResourceStatus { name: self.name }
    }
}
