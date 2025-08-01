// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The wrapper that contains the Audit Manager role information of the current user. This includes the role type and IAM Amazon Resource Name (ARN).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Role {
    /// <p>The type of customer persona.</p><note>
    /// <p>In <code>CreateAssessment</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>UpdateSettings</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>BatchCreateDelegationByAssessment</code>, <code>roleType</code> can only be <code>RESOURCE_OWNER</code>.</p>
    /// </note>
    pub role_type: crate::types::RoleType,
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub role_arn: ::std::string::String,
}
impl Role {
    /// <p>The type of customer persona.</p><note>
    /// <p>In <code>CreateAssessment</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>UpdateSettings</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>BatchCreateDelegationByAssessment</code>, <code>roleType</code> can only be <code>RESOURCE_OWNER</code>.</p>
    /// </note>
    pub fn role_type(&self) -> &crate::types::RoleType {
        &self.role_type
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
}
impl Role {
    /// Creates a new builder-style object to manufacture [`Role`](crate::types::Role).
    pub fn builder() -> crate::types::builders::RoleBuilder {
        crate::types::builders::RoleBuilder::default()
    }
}

/// A builder for [`Role`](crate::types::Role).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RoleBuilder {
    pub(crate) role_type: ::std::option::Option<crate::types::RoleType>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl RoleBuilder {
    /// <p>The type of customer persona.</p><note>
    /// <p>In <code>CreateAssessment</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>UpdateSettings</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>BatchCreateDelegationByAssessment</code>, <code>roleType</code> can only be <code>RESOURCE_OWNER</code>.</p>
    /// </note>
    /// This field is required.
    pub fn role_type(mut self, input: crate::types::RoleType) -> Self {
        self.role_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of customer persona.</p><note>
    /// <p>In <code>CreateAssessment</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>UpdateSettings</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>BatchCreateDelegationByAssessment</code>, <code>roleType</code> can only be <code>RESOURCE_OWNER</code>.</p>
    /// </note>
    pub fn set_role_type(mut self, input: ::std::option::Option<crate::types::RoleType>) -> Self {
        self.role_type = input;
        self
    }
    /// <p>The type of customer persona.</p><note>
    /// <p>In <code>CreateAssessment</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>UpdateSettings</code>, <code>roleType</code> can only be <code>PROCESS_OWNER</code>.</p>
    /// <p>In <code>BatchCreateDelegationByAssessment</code>, <code>roleType</code> can only be <code>RESOURCE_OWNER</code>.</p>
    /// </note>
    pub fn get_role_type(&self) -> &::std::option::Option<crate::types::RoleType> {
        &self.role_type
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`Role`](crate::types::Role).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_type`](crate::types::builders::RoleBuilder::role_type)
    /// - [`role_arn`](crate::types::builders::RoleBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::Role, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Role {
            role_type: self.role_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_type",
                    "role_type was not specified but it is required when building Role",
                )
            })?,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building Role",
                )
            })?,
        })
    }
}
