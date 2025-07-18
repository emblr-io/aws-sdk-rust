// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container object for the session details that are associated with a workflow.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceMetadata {
    /// <p>The Server ID (<code>ServerId</code>), Session ID (<code>SessionId</code>) and user (<code>UserName</code>) make up the <code>UserDetails</code>.</p>
    pub user_details: ::std::option::Option<crate::types::UserDetails>,
}
impl ServiceMetadata {
    /// <p>The Server ID (<code>ServerId</code>), Session ID (<code>SessionId</code>) and user (<code>UserName</code>) make up the <code>UserDetails</code>.</p>
    pub fn user_details(&self) -> ::std::option::Option<&crate::types::UserDetails> {
        self.user_details.as_ref()
    }
}
impl ServiceMetadata {
    /// Creates a new builder-style object to manufacture [`ServiceMetadata`](crate::types::ServiceMetadata).
    pub fn builder() -> crate::types::builders::ServiceMetadataBuilder {
        crate::types::builders::ServiceMetadataBuilder::default()
    }
}

/// A builder for [`ServiceMetadata`](crate::types::ServiceMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceMetadataBuilder {
    pub(crate) user_details: ::std::option::Option<crate::types::UserDetails>,
}
impl ServiceMetadataBuilder {
    /// <p>The Server ID (<code>ServerId</code>), Session ID (<code>SessionId</code>) and user (<code>UserName</code>) make up the <code>UserDetails</code>.</p>
    /// This field is required.
    pub fn user_details(mut self, input: crate::types::UserDetails) -> Self {
        self.user_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Server ID (<code>ServerId</code>), Session ID (<code>SessionId</code>) and user (<code>UserName</code>) make up the <code>UserDetails</code>.</p>
    pub fn set_user_details(mut self, input: ::std::option::Option<crate::types::UserDetails>) -> Self {
        self.user_details = input;
        self
    }
    /// <p>The Server ID (<code>ServerId</code>), Session ID (<code>SessionId</code>) and user (<code>UserName</code>) make up the <code>UserDetails</code>.</p>
    pub fn get_user_details(&self) -> &::std::option::Option<crate::types::UserDetails> {
        &self.user_details
    }
    /// Consumes the builder and constructs a [`ServiceMetadata`](crate::types::ServiceMetadata).
    pub fn build(self) -> crate::types::ServiceMetadata {
        crate::types::ServiceMetadata {
            user_details: self.user_details,
        }
    }
}
