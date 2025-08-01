// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetClusterSessionCredentialsInput {
    /// <p>The unique identifier of the cluster.</p>
    pub cluster_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the runtime role for interactive workload submission on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    pub execution_role_arn: ::std::option::Option<::std::string::String>,
}
impl GetClusterSessionCredentialsInput {
    /// <p>The unique identifier of the cluster.</p>
    pub fn cluster_id(&self) -> ::std::option::Option<&str> {
        self.cluster_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for interactive workload submission on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    pub fn execution_role_arn(&self) -> ::std::option::Option<&str> {
        self.execution_role_arn.as_deref()
    }
}
impl GetClusterSessionCredentialsInput {
    /// Creates a new builder-style object to manufacture [`GetClusterSessionCredentialsInput`](crate::operation::get_cluster_session_credentials::GetClusterSessionCredentialsInput).
    pub fn builder() -> crate::operation::get_cluster_session_credentials::builders::GetClusterSessionCredentialsInputBuilder {
        crate::operation::get_cluster_session_credentials::builders::GetClusterSessionCredentialsInputBuilder::default()
    }
}

/// A builder for [`GetClusterSessionCredentialsInput`](crate::operation::get_cluster_session_credentials::GetClusterSessionCredentialsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetClusterSessionCredentialsInputBuilder {
    pub(crate) cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) execution_role_arn: ::std::option::Option<::std::string::String>,
}
impl GetClusterSessionCredentialsInputBuilder {
    /// <p>The unique identifier of the cluster.</p>
    /// This field is required.
    pub fn cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the cluster.</p>
    pub fn set_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_id = input;
        self
    }
    /// <p>The unique identifier of the cluster.</p>
    pub fn get_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_id
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for interactive workload submission on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    pub fn execution_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for interactive workload submission on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    pub fn set_execution_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the runtime role for interactive workload submission on the cluster. The runtime role can be a cross-account IAM role. The runtime role ARN is a combination of account ID, role name, and role type using the following format: <code>arn:partition:service:region:account:resource</code>.</p>
    pub fn get_execution_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role_arn
    }
    /// Consumes the builder and constructs a [`GetClusterSessionCredentialsInput`](crate::operation::get_cluster_session_credentials::GetClusterSessionCredentialsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_cluster_session_credentials::GetClusterSessionCredentialsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_cluster_session_credentials::GetClusterSessionCredentialsInput {
            cluster_id: self.cluster_id,
            execution_role_arn: self.execution_role_arn,
        })
    }
}
