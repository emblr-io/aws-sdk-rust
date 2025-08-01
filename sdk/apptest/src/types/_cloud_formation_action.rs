// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the CloudFormation action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudFormationAction {
    /// <p>The resource of the CloudFormation action.</p>
    pub resource: ::std::string::String,
    /// <p>The action type of the CloudFormation action.</p>
    pub action_type: ::std::option::Option<crate::types::CloudFormationActionType>,
}
impl CloudFormationAction {
    /// <p>The resource of the CloudFormation action.</p>
    pub fn resource(&self) -> &str {
        use std::ops::Deref;
        self.resource.deref()
    }
    /// <p>The action type of the CloudFormation action.</p>
    pub fn action_type(&self) -> ::std::option::Option<&crate::types::CloudFormationActionType> {
        self.action_type.as_ref()
    }
}
impl CloudFormationAction {
    /// Creates a new builder-style object to manufacture [`CloudFormationAction`](crate::types::CloudFormationAction).
    pub fn builder() -> crate::types::builders::CloudFormationActionBuilder {
        crate::types::builders::CloudFormationActionBuilder::default()
    }
}

/// A builder for [`CloudFormationAction`](crate::types::CloudFormationAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudFormationActionBuilder {
    pub(crate) resource: ::std::option::Option<::std::string::String>,
    pub(crate) action_type: ::std::option::Option<crate::types::CloudFormationActionType>,
}
impl CloudFormationActionBuilder {
    /// <p>The resource of the CloudFormation action.</p>
    /// This field is required.
    pub fn resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource of the CloudFormation action.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The resource of the CloudFormation action.</p>
    pub fn get_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource
    }
    /// <p>The action type of the CloudFormation action.</p>
    pub fn action_type(mut self, input: crate::types::CloudFormationActionType) -> Self {
        self.action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action type of the CloudFormation action.</p>
    pub fn set_action_type(mut self, input: ::std::option::Option<crate::types::CloudFormationActionType>) -> Self {
        self.action_type = input;
        self
    }
    /// <p>The action type of the CloudFormation action.</p>
    pub fn get_action_type(&self) -> &::std::option::Option<crate::types::CloudFormationActionType> {
        &self.action_type
    }
    /// Consumes the builder and constructs a [`CloudFormationAction`](crate::types::CloudFormationAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource`](crate::types::builders::CloudFormationActionBuilder::resource)
    pub fn build(self) -> ::std::result::Result<crate::types::CloudFormationAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudFormationAction {
            resource: self.resource.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource",
                    "resource was not specified but it is required when building CloudFormationAction",
                )
            })?,
            action_type: self.action_type,
        })
    }
}
