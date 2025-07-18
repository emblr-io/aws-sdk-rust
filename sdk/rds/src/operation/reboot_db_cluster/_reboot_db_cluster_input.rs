// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RebootDbClusterInput {
    /// <p>The DB cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBCluster.</p></li>
    /// </ul>
    pub db_cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl RebootDbClusterInput {
    /// <p>The DB cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBCluster.</p></li>
    /// </ul>
    pub fn db_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.db_cluster_identifier.as_deref()
    }
}
impl RebootDbClusterInput {
    /// Creates a new builder-style object to manufacture [`RebootDbClusterInput`](crate::operation::reboot_db_cluster::RebootDbClusterInput).
    pub fn builder() -> crate::operation::reboot_db_cluster::builders::RebootDbClusterInputBuilder {
        crate::operation::reboot_db_cluster::builders::RebootDbClusterInputBuilder::default()
    }
}

/// A builder for [`RebootDbClusterInput`](crate::operation::reboot_db_cluster::RebootDbClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RebootDbClusterInputBuilder {
    pub(crate) db_cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl RebootDbClusterInputBuilder {
    /// <p>The DB cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBCluster.</p></li>
    /// </ul>
    /// This field is required.
    pub fn db_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DB cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBCluster.</p></li>
    /// </ul>
    pub fn set_db_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_cluster_identifier = input;
        self
    }
    /// <p>The DB cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DBCluster.</p></li>
    /// </ul>
    pub fn get_db_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_cluster_identifier
    }
    /// Consumes the builder and constructs a [`RebootDbClusterInput`](crate::operation::reboot_db_cluster::RebootDbClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::reboot_db_cluster::RebootDbClusterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::reboot_db_cluster::RebootDbClusterInput {
            db_cluster_identifier: self.db_cluster_identifier,
        })
    }
}
