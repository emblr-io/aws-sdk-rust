// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcePermissionInput {
    /// <p></p>
    pub action_type: ::std::option::Option<crate::types::PermissionActionType>,
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetResourcePermissionInput {
    /// <p></p>
    pub fn action_type(&self) -> ::std::option::Option<&crate::types::PermissionActionType> {
        self.action_type.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl GetResourcePermissionInput {
    /// Creates a new builder-style object to manufacture [`GetResourcePermissionInput`](crate::operation::get_resource_permission::GetResourcePermissionInput).
    pub fn builder() -> crate::operation::get_resource_permission::builders::GetResourcePermissionInputBuilder {
        crate::operation::get_resource_permission::builders::GetResourcePermissionInputBuilder::default()
    }
}

/// A builder for [`GetResourcePermissionInput`](crate::operation::get_resource_permission::GetResourcePermissionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcePermissionInputBuilder {
    pub(crate) action_type: ::std::option::Option<crate::types::PermissionActionType>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetResourcePermissionInputBuilder {
    /// <p></p>
    pub fn action_type(mut self, input: crate::types::PermissionActionType) -> Self {
        self.action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_action_type(mut self, input: ::std::option::Option<crate::types::PermissionActionType>) -> Self {
        self.action_type = input;
        self
    }
    /// <p></p>
    pub fn get_action_type(&self) -> &::std::option::Option<crate::types::PermissionActionType> {
        &self.action_type
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`GetResourcePermissionInput`](crate::operation::get_resource_permission::GetResourcePermissionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resource_permission::GetResourcePermissionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_resource_permission::GetResourcePermissionInput {
            action_type: self.action_type,
            resource_arn: self.resource_arn,
        })
    }
}
