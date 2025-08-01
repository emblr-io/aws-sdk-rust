// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyGlobalClusterInput {
    /// <p>The cluster identifier for the global cluster to modify. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global database cluster.</p></li>
    /// </ul>
    pub global_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The new cluster identifier for the global database cluster. This value is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub new_global_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to enable deletion protection for the global database cluster. The global database cluster can't be deleted when deletion protection is enabled.</p>
    pub deletion_protection: ::std::option::Option<bool>,
    /// <p>The version number of the database engine to which you want to upgrade.</p>
    /// <p>To list all of the available engine versions for <code>aurora-mysql</code> (for MySQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-mysql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    /// <p>To list all of the available engine versions for <code>aurora-postgresql</code> (for PostgreSQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-postgresql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to allow major version upgrades.</p>
    /// <p>Constraints: Must be enabled if you specify a value for the <code>EngineVersion</code> parameter that's a different major version than the global cluster's current version.</p>
    /// <p>If you upgrade the major version of a global database, the cluster and DB instance parameter groups are set to the default parameter groups for the new version. Apply any custom parameter groups after completing the upgrade.</p>
    pub allow_major_version_upgrade: ::std::option::Option<bool>,
}
impl ModifyGlobalClusterInput {
    /// <p>The cluster identifier for the global cluster to modify. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global database cluster.</p></li>
    /// </ul>
    pub fn global_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.global_cluster_identifier.as_deref()
    }
    /// <p>The new cluster identifier for the global database cluster. This value is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn new_global_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.new_global_cluster_identifier.as_deref()
    }
    /// <p>Specifies whether to enable deletion protection for the global database cluster. The global database cluster can't be deleted when deletion protection is enabled.</p>
    pub fn deletion_protection(&self) -> ::std::option::Option<bool> {
        self.deletion_protection
    }
    /// <p>The version number of the database engine to which you want to upgrade.</p>
    /// <p>To list all of the available engine versions for <code>aurora-mysql</code> (for MySQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-mysql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    /// <p>To list all of the available engine versions for <code>aurora-postgresql</code> (for PostgreSQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-postgresql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>Specifies whether to allow major version upgrades.</p>
    /// <p>Constraints: Must be enabled if you specify a value for the <code>EngineVersion</code> parameter that's a different major version than the global cluster's current version.</p>
    /// <p>If you upgrade the major version of a global database, the cluster and DB instance parameter groups are set to the default parameter groups for the new version. Apply any custom parameter groups after completing the upgrade.</p>
    pub fn allow_major_version_upgrade(&self) -> ::std::option::Option<bool> {
        self.allow_major_version_upgrade
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
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) allow_major_version_upgrade: ::std::option::Option<bool>,
}
impl ModifyGlobalClusterInputBuilder {
    /// <p>The cluster identifier for the global cluster to modify. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global database cluster.</p></li>
    /// </ul>
    pub fn global_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier for the global cluster to modify. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global database cluster.</p></li>
    /// </ul>
    pub fn set_global_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_cluster_identifier = input;
        self
    }
    /// <p>The cluster identifier for the global cluster to modify. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing global database cluster.</p></li>
    /// </ul>
    pub fn get_global_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_cluster_identifier
    }
    /// <p>The new cluster identifier for the global database cluster. This value is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn new_global_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_global_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new cluster identifier for the global database cluster. This value is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn set_new_global_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_global_cluster_identifier = input;
        self
    }
    /// <p>The new cluster identifier for the global database cluster. This value is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Can't end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster2</code></p>
    pub fn get_new_global_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_global_cluster_identifier
    }
    /// <p>Specifies whether to enable deletion protection for the global database cluster. The global database cluster can't be deleted when deletion protection is enabled.</p>
    pub fn deletion_protection(mut self, input: bool) -> Self {
        self.deletion_protection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to enable deletion protection for the global database cluster. The global database cluster can't be deleted when deletion protection is enabled.</p>
    pub fn set_deletion_protection(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deletion_protection = input;
        self
    }
    /// <p>Specifies whether to enable deletion protection for the global database cluster. The global database cluster can't be deleted when deletion protection is enabled.</p>
    pub fn get_deletion_protection(&self) -> &::std::option::Option<bool> {
        &self.deletion_protection
    }
    /// <p>The version number of the database engine to which you want to upgrade.</p>
    /// <p>To list all of the available engine versions for <code>aurora-mysql</code> (for MySQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-mysql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    /// <p>To list all of the available engine versions for <code>aurora-postgresql</code> (for PostgreSQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-postgresql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of the database engine to which you want to upgrade.</p>
    /// <p>To list all of the available engine versions for <code>aurora-mysql</code> (for MySQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-mysql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    /// <p>To list all of the available engine versions for <code>aurora-postgresql</code> (for PostgreSQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-postgresql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The version number of the database engine to which you want to upgrade.</p>
    /// <p>To list all of the available engine versions for <code>aurora-mysql</code> (for MySQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-mysql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    /// <p>To list all of the available engine versions for <code>aurora-postgresql</code> (for PostgreSQL-based Aurora global databases), use the following command:</p>
    /// <p><code>aws rds describe-db-engine-versions --engine aurora-postgresql --query '*\[\]|\[?SupportsGlobalDatabases == `true`\].\[EngineVersion\]'</code></p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>Specifies whether to allow major version upgrades.</p>
    /// <p>Constraints: Must be enabled if you specify a value for the <code>EngineVersion</code> parameter that's a different major version than the global cluster's current version.</p>
    /// <p>If you upgrade the major version of a global database, the cluster and DB instance parameter groups are set to the default parameter groups for the new version. Apply any custom parameter groups after completing the upgrade.</p>
    pub fn allow_major_version_upgrade(mut self, input: bool) -> Self {
        self.allow_major_version_upgrade = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to allow major version upgrades.</p>
    /// <p>Constraints: Must be enabled if you specify a value for the <code>EngineVersion</code> parameter that's a different major version than the global cluster's current version.</p>
    /// <p>If you upgrade the major version of a global database, the cluster and DB instance parameter groups are set to the default parameter groups for the new version. Apply any custom parameter groups after completing the upgrade.</p>
    pub fn set_allow_major_version_upgrade(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_major_version_upgrade = input;
        self
    }
    /// <p>Specifies whether to allow major version upgrades.</p>
    /// <p>Constraints: Must be enabled if you specify a value for the <code>EngineVersion</code> parameter that's a different major version than the global cluster's current version.</p>
    /// <p>If you upgrade the major version of a global database, the cluster and DB instance parameter groups are set to the default parameter groups for the new version. Apply any custom parameter groups after completing the upgrade.</p>
    pub fn get_allow_major_version_upgrade(&self) -> &::std::option::Option<bool> {
        &self.allow_major_version_upgrade
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
            engine_version: self.engine_version,
            allow_major_version_upgrade: self.allow_major_version_upgrade,
        })
    }
}
