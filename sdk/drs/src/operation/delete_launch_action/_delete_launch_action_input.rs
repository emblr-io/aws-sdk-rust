// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLaunchActionInput {
    /// <p>Launch configuration template Id or Source Server Id</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Launch action Id.</p>
    pub action_id: ::std::option::Option<::std::string::String>,
}
impl DeleteLaunchActionInput {
    /// <p>Launch configuration template Id or Source Server Id</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>Launch action Id.</p>
    pub fn action_id(&self) -> ::std::option::Option<&str> {
        self.action_id.as_deref()
    }
}
impl DeleteLaunchActionInput {
    /// Creates a new builder-style object to manufacture [`DeleteLaunchActionInput`](crate::operation::delete_launch_action::DeleteLaunchActionInput).
    pub fn builder() -> crate::operation::delete_launch_action::builders::DeleteLaunchActionInputBuilder {
        crate::operation::delete_launch_action::builders::DeleteLaunchActionInputBuilder::default()
    }
}

/// A builder for [`DeleteLaunchActionInput`](crate::operation::delete_launch_action::DeleteLaunchActionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLaunchActionInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) action_id: ::std::option::Option<::std::string::String>,
}
impl DeleteLaunchActionInputBuilder {
    /// <p>Launch configuration template Id or Source Server Id</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Launch configuration template Id or Source Server Id</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>Launch configuration template Id or Source Server Id</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>Launch action Id.</p>
    /// This field is required.
    pub fn action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Launch action Id.</p>
    pub fn set_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_id = input;
        self
    }
    /// <p>Launch action Id.</p>
    pub fn get_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_id
    }
    /// Consumes the builder and constructs a [`DeleteLaunchActionInput`](crate::operation::delete_launch_action::DeleteLaunchActionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_launch_action::DeleteLaunchActionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_launch_action::DeleteLaunchActionInput {
            resource_id: self.resource_id,
            action_id: self.action_id,
        })
    }
}
