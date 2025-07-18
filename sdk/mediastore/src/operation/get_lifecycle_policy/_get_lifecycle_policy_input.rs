// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLifecyclePolicyInput {
    /// <p>The name of the container that the object lifecycle policy is assigned to.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
}
impl GetLifecyclePolicyInput {
    /// <p>The name of the container that the object lifecycle policy is assigned to.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
}
impl GetLifecyclePolicyInput {
    /// Creates a new builder-style object to manufacture [`GetLifecyclePolicyInput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyInput).
    pub fn builder() -> crate::operation::get_lifecycle_policy::builders::GetLifecyclePolicyInputBuilder {
        crate::operation::get_lifecycle_policy::builders::GetLifecyclePolicyInputBuilder::default()
    }
}

/// A builder for [`GetLifecyclePolicyInput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLifecyclePolicyInputBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
}
impl GetLifecyclePolicyInputBuilder {
    /// <p>The name of the container that the object lifecycle policy is assigned to.</p>
    /// This field is required.
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container that the object lifecycle policy is assigned to.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container that the object lifecycle policy is assigned to.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// Consumes the builder and constructs a [`GetLifecyclePolicyInput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_lifecycle_policy::GetLifecyclePolicyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_lifecycle_policy::GetLifecyclePolicyInput {
            container_name: self.container_name,
        })
    }
}
