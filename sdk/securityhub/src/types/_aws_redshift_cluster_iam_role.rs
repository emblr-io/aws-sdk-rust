// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An IAM role that the cluster can use to access other Amazon Web Services services.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsRedshiftClusterIamRole {
    /// <p>The status of the IAM role's association with the cluster.</p>
    /// <p>Valid values: <code>in-sync</code> | <code>adding</code> | <code>removing</code></p>
    pub apply_status: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM role.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl AwsRedshiftClusterIamRole {
    /// <p>The status of the IAM role's association with the cluster.</p>
    /// <p>Valid values: <code>in-sync</code> | <code>adding</code> | <code>removing</code></p>
    pub fn apply_status(&self) -> ::std::option::Option<&str> {
        self.apply_status.as_deref()
    }
    /// <p>The ARN of the IAM role.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
}
impl AwsRedshiftClusterIamRole {
    /// Creates a new builder-style object to manufacture [`AwsRedshiftClusterIamRole`](crate::types::AwsRedshiftClusterIamRole).
    pub fn builder() -> crate::types::builders::AwsRedshiftClusterIamRoleBuilder {
        crate::types::builders::AwsRedshiftClusterIamRoleBuilder::default()
    }
}

/// A builder for [`AwsRedshiftClusterIamRole`](crate::types::AwsRedshiftClusterIamRole).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsRedshiftClusterIamRoleBuilder {
    pub(crate) apply_status: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl AwsRedshiftClusterIamRoleBuilder {
    /// <p>The status of the IAM role's association with the cluster.</p>
    /// <p>Valid values: <code>in-sync</code> | <code>adding</code> | <code>removing</code></p>
    pub fn apply_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.apply_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the IAM role's association with the cluster.</p>
    /// <p>Valid values: <code>in-sync</code> | <code>adding</code> | <code>removing</code></p>
    pub fn set_apply_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.apply_status = input;
        self
    }
    /// <p>The status of the IAM role's association with the cluster.</p>
    /// <p>Valid values: <code>in-sync</code> | <code>adding</code> | <code>removing</code></p>
    pub fn get_apply_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.apply_status
    }
    /// <p>The ARN of the IAM role.</p>
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// Consumes the builder and constructs a [`AwsRedshiftClusterIamRole`](crate::types::AwsRedshiftClusterIamRole).
    pub fn build(self) -> crate::types::AwsRedshiftClusterIamRole {
        crate::types::AwsRedshiftClusterIamRole {
            apply_status: self.apply_status,
            iam_role_arn: self.iam_role_arn,
        }
    }
}
