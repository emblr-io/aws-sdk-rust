// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a target for an action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionTarget {
    /// <p>The resource type of the target.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
}
impl ActionTarget {
    /// <p>The resource type of the target.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
}
impl ActionTarget {
    /// Creates a new builder-style object to manufacture [`ActionTarget`](crate::types::ActionTarget).
    pub fn builder() -> crate::types::builders::ActionTargetBuilder {
        crate::types::builders::ActionTargetBuilder::default()
    }
}

/// A builder for [`ActionTarget`](crate::types::ActionTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionTargetBuilder {
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
}
impl ActionTargetBuilder {
    /// <p>The resource type of the target.</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource type of the target.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type of the target.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// Consumes the builder and constructs a [`ActionTarget`](crate::types::ActionTarget).
    pub fn build(self) -> crate::types::ActionTarget {
        crate::types::ActionTarget {
            resource_type: self.resource_type,
        }
    }
}
