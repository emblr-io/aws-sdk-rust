// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Identity and Access Management (IAM) role that is associated with a cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbClusterRole {
    /// <p>The Amazon Resource Name (ARN) of the IAMrole that is associated with the DB cluster.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Describes the state of association between the IAMrole and the cluster. The <code>Status</code> property returns one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - The IAMrole ARN is associated with the cluster and can be used to access other Amazon Web Services services on your behalf.</p></li>
    /// <li>
    /// <p><code>PENDING</code> - The IAMrole ARN is being associated with the cluster.</p></li>
    /// <li>
    /// <p><code>INVALID</code> - The IAMrole ARN is associated with the cluster, but the cluster cannot assume the IAMrole to access other Amazon Web Services services on your behalf.</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
}
impl DbClusterRole {
    /// <p>The Amazon Resource Name (ARN) of the IAMrole that is associated with the DB cluster.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Describes the state of association between the IAMrole and the cluster. The <code>Status</code> property returns one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - The IAMrole ARN is associated with the cluster and can be used to access other Amazon Web Services services on your behalf.</p></li>
    /// <li>
    /// <p><code>PENDING</code> - The IAMrole ARN is being associated with the cluster.</p></li>
    /// <li>
    /// <p><code>INVALID</code> - The IAMrole ARN is associated with the cluster, but the cluster cannot assume the IAMrole to access other Amazon Web Services services on your behalf.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl DbClusterRole {
    /// Creates a new builder-style object to manufacture [`DbClusterRole`](crate::types::DbClusterRole).
    pub fn builder() -> crate::types::builders::DbClusterRoleBuilder {
        crate::types::builders::DbClusterRoleBuilder::default()
    }
}

/// A builder for [`DbClusterRole`](crate::types::DbClusterRole).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbClusterRoleBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl DbClusterRoleBuilder {
    /// <p>The Amazon Resource Name (ARN) of the IAMrole that is associated with the DB cluster.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAMrole that is associated with the DB cluster.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAMrole that is associated with the DB cluster.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>Describes the state of association between the IAMrole and the cluster. The <code>Status</code> property returns one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - The IAMrole ARN is associated with the cluster and can be used to access other Amazon Web Services services on your behalf.</p></li>
    /// <li>
    /// <p><code>PENDING</code> - The IAMrole ARN is being associated with the cluster.</p></li>
    /// <li>
    /// <p><code>INVALID</code> - The IAMrole ARN is associated with the cluster, but the cluster cannot assume the IAMrole to access other Amazon Web Services services on your behalf.</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Describes the state of association between the IAMrole and the cluster. The <code>Status</code> property returns one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - The IAMrole ARN is associated with the cluster and can be used to access other Amazon Web Services services on your behalf.</p></li>
    /// <li>
    /// <p><code>PENDING</code> - The IAMrole ARN is being associated with the cluster.</p></li>
    /// <li>
    /// <p><code>INVALID</code> - The IAMrole ARN is associated with the cluster, but the cluster cannot assume the IAMrole to access other Amazon Web Services services on your behalf.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>Describes the state of association between the IAMrole and the cluster. The <code>Status</code> property returns one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - The IAMrole ARN is associated with the cluster and can be used to access other Amazon Web Services services on your behalf.</p></li>
    /// <li>
    /// <p><code>PENDING</code> - The IAMrole ARN is being associated with the cluster.</p></li>
    /// <li>
    /// <p><code>INVALID</code> - The IAMrole ARN is associated with the cluster, but the cluster cannot assume the IAMrole to access other Amazon Web Services services on your behalf.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`DbClusterRole`](crate::types::DbClusterRole).
    pub fn build(self) -> crate::types::DbClusterRole {
        crate::types::DbClusterRole {
            role_arn: self.role_arn,
            status: self.status,
        }
    }
}
