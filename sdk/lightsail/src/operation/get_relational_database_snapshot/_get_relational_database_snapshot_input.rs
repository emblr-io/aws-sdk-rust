// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabaseSnapshotInput {
    /// <p>The name of the database snapshot for which to get information.</p>
    pub relational_database_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetRelationalDatabaseSnapshotInput {
    /// <p>The name of the database snapshot for which to get information.</p>
    pub fn relational_database_snapshot_name(&self) -> ::std::option::Option<&str> {
        self.relational_database_snapshot_name.as_deref()
    }
}
impl GetRelationalDatabaseSnapshotInput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabaseSnapshotInput`](crate::operation::get_relational_database_snapshot::GetRelationalDatabaseSnapshotInput).
    pub fn builder() -> crate::operation::get_relational_database_snapshot::builders::GetRelationalDatabaseSnapshotInputBuilder {
        crate::operation::get_relational_database_snapshot::builders::GetRelationalDatabaseSnapshotInputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabaseSnapshotInput`](crate::operation::get_relational_database_snapshot::GetRelationalDatabaseSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabaseSnapshotInputBuilder {
    pub(crate) relational_database_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetRelationalDatabaseSnapshotInputBuilder {
    /// <p>The name of the database snapshot for which to get information.</p>
    /// This field is required.
    pub fn relational_database_snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.relational_database_snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database snapshot for which to get information.</p>
    pub fn set_relational_database_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.relational_database_snapshot_name = input;
        self
    }
    /// <p>The name of the database snapshot for which to get information.</p>
    pub fn get_relational_database_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.relational_database_snapshot_name
    }
    /// Consumes the builder and constructs a [`GetRelationalDatabaseSnapshotInput`](crate::operation::get_relational_database_snapshot::GetRelationalDatabaseSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_relational_database_snapshot::GetRelationalDatabaseSnapshotInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_relational_database_snapshot::GetRelationalDatabaseSnapshotInput {
            relational_database_snapshot_name: self.relational_database_snapshot_name,
        })
    }
}
