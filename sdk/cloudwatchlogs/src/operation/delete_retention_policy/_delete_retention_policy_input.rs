// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRetentionPolicyInput {
    /// <p>The name of the log group.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteRetentionPolicyInput {
    /// <p>The name of the log group.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
}
impl DeleteRetentionPolicyInput {
    /// Creates a new builder-style object to manufacture [`DeleteRetentionPolicyInput`](crate::operation::delete_retention_policy::DeleteRetentionPolicyInput).
    pub fn builder() -> crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyInputBuilder {
        crate::operation::delete_retention_policy::builders::DeleteRetentionPolicyInputBuilder::default()
    }
}

/// A builder for [`DeleteRetentionPolicyInput`](crate::operation::delete_retention_policy::DeleteRetentionPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRetentionPolicyInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteRetentionPolicyInputBuilder {
    /// <p>The name of the log group.</p>
    /// This field is required.
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// Consumes the builder and constructs a [`DeleteRetentionPolicyInput`](crate::operation::delete_retention_policy::DeleteRetentionPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_retention_policy::DeleteRetentionPolicyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_retention_policy::DeleteRetentionPolicyInput {
            log_group_name: self.log_group_name,
        })
    }
}
