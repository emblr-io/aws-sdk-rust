// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetContainerPolicyInput {
    /// <p>The name of the container.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
}
impl GetContainerPolicyInput {
    /// <p>The name of the container.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
}
impl GetContainerPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetContainerPolicyInput`](crate::operation::get_container_policy::GetContainerPolicyInput).
    pub fn builder() -> crate::operation::get_container_policy::builders::GetContainerPolicyInputBuilder {
        crate::operation::get_container_policy::builders::GetContainerPolicyInputBuilder::default()
    }
}

/// A builder for [`GetContainerPolicyInput`](crate::operation::get_container_policy::GetContainerPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetContainerPolicyInputBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
}
impl GetContainerPolicyInputBuilder {
    /// <p>The name of the container.</p>
    /// This field is required.
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// Consumes the builder and constructs a [`GetContainerPolicyInput`](crate::operation::get_container_policy::GetContainerPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_container_policy::GetContainerPolicyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_container_policy::GetContainerPolicyInput {
            container_name: self.container_name,
        })
    }
}
