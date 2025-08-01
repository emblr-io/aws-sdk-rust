// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReplicationSubnetGroupInput {
    /// <p>The subnet group name of the replication instance.</p>
    pub replication_subnet_group_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationSubnetGroupInput {
    /// <p>The subnet group name of the replication instance.</p>
    pub fn replication_subnet_group_identifier(&self) -> ::std::option::Option<&str> {
        self.replication_subnet_group_identifier.as_deref()
    }
}
impl DeleteReplicationSubnetGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteReplicationSubnetGroupInput`](crate::operation::delete_replication_subnet_group::DeleteReplicationSubnetGroupInput).
    pub fn builder() -> crate::operation::delete_replication_subnet_group::builders::DeleteReplicationSubnetGroupInputBuilder {
        crate::operation::delete_replication_subnet_group::builders::DeleteReplicationSubnetGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteReplicationSubnetGroupInput`](crate::operation::delete_replication_subnet_group::DeleteReplicationSubnetGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReplicationSubnetGroupInputBuilder {
    pub(crate) replication_subnet_group_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationSubnetGroupInputBuilder {
    /// <p>The subnet group name of the replication instance.</p>
    /// This field is required.
    pub fn replication_subnet_group_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_subnet_group_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subnet group name of the replication instance.</p>
    pub fn set_replication_subnet_group_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_subnet_group_identifier = input;
        self
    }
    /// <p>The subnet group name of the replication instance.</p>
    pub fn get_replication_subnet_group_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_subnet_group_identifier
    }
    /// Consumes the builder and constructs a [`DeleteReplicationSubnetGroupInput`](crate::operation::delete_replication_subnet_group::DeleteReplicationSubnetGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_replication_subnet_group::DeleteReplicationSubnetGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_replication_subnet_group::DeleteReplicationSubnetGroupInput {
            replication_subnet_group_identifier: self.replication_subnet_group_identifier,
        })
    }
}
