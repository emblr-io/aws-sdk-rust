// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input to <code>ModifyGlobalCluster</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyGlobalClusterInput {
    /// <p>The identifier for the global cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// </ul>
    pub global_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The new identifier for a global cluster when you modify a global cluster. This value is stored as a lowercase string.</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens</p>
    /// <p>The first character must be a letter</p>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub new_global_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Indicates if the global cluster has deletion protection enabled. The global cluster can't be deleted when deletion protection is enabled.</p>
    pub deletion_protection: ::std::option::Option<bool>,
}
impl ModifyGlobalClusterInput {
    /// <p>The identifier for the global cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// </ul>
    pub fn global_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.global_cluster_identifier.as_deref()
    }
    /// <p>The new identifier for a global cluster when you modify a global cluster. This value is stored as a lowercase string.</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens</p>
    /// <p>The first character must be a letter</p>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn new_global_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.new_global_cluster_identifier.as_deref()
    }
    /// <p>Indicates if the global cluster has deletion protection enabled. The global cluster can't be deleted when deletion protection is enabled.</p>
    pub fn deletion_protection(&self) -> ::std::option::Option<bool> {
        self.deletion_protection
    }
}
impl ModifyGlobalClusterInput {
    /// Creates a new builder-style object to manufacture [`ModifyGlobalClusterInput`](crate::operation::modify_global_cluster::ModifyGlobalClusterInput).
    pub fn builder() -> crate::operation::modify_global_cluster::builders::ModifyGlobalClusterInputBuilder {
        crate::operation::modify_global_cluster::builders::ModifyGlobalClusterInputBuilder::default()
    }
}

/// A builder for [`ModifyGlobalClusterInput`](crate::operation::modify_global_cluster::ModifyGlobalClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyGlobalClusterInputBuilder {
    pub(crate) global_cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) new_global_cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) deletion_protection: ::std::option::Option<bool>,
}
impl ModifyGlobalClusterInputBuilder {
    /// <p>The identifier for the global cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// </ul>
    /// This field is required.
    pub fn global_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the global cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// </ul>
    pub fn set_global_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_cluster_identifier = input;
        self
    }
    /// <p>The identifier for the global cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global cluster.</p></li>
    /// </ul>
    pub fn get_global_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_cluster_identifier
    }
    /// <p>The new identifier for a global cluster when you modify a global cluster. This value is stored as a lowercase string.</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens</p>
    /// <p>The first character must be a letter</p>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn new_global_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_global_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new identifier for a global cluster when you modify a global cluster. This value is stored as a lowercase string.</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens</p>
    /// <p>The first character must be a letter</p>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn set_new_global_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_global_cluster_identifier = input;
        self
    }
    /// <p>The new identifier for a global cluster when you modify a global cluster. This value is stored as a lowercase string.</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens</p>
    /// <p>The first character must be a letter</p>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn get_new_global_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_global_cluster_identifier
    }
    /// <p>Indicates if the global cluster has deletion protection enabled. The global cluster can't be deleted when deletion protection is enabled.</p>
    pub fn deletion_protection(mut self, input: bool) -> Self {
        self.deletion_protection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the global cluster has deletion protection enabled. The global cluster can't be deleted when deletion protection is enabled.</p>
    pub fn set_deletion_protection(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deletion_protection = input;
        self
    }
    /// <p>Indicates if the global cluster has deletion protection enabled. The global cluster can't be deleted when deletion protection is enabled.</p>
    pub fn get_deletion_protection(&self) -> &::std::option::Option<bool> {
        &self.deletion_protection
    }
    /// Consumes the builder and constructs a [`ModifyGlobalClusterInput`](crate::operation::modify_global_cluster::ModifyGlobalClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::modify_global_cluster::ModifyGlobalClusterInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::modify_global_cluster::ModifyGlobalClusterInput {
            global_cluster_identifier: self.global_cluster_identifier,
            new_global_cluster_identifier: self.new_global_cluster_identifier,
            deletion_protection: self.deletion_protection,
        })
    }
}
