// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a pending database value modification.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PendingModifiedRelationalDatabaseValues {
    /// <p>The password for the master user of the database.</p>
    pub master_user_password: ::std::option::Option<::std::string::String>,
    /// <p>The database engine version.</p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>A Boolean value indicating whether automated backup retention is enabled.</p>
    pub backup_retention_enabled: ::std::option::Option<bool>,
}
impl PendingModifiedRelationalDatabaseValues {
    /// <p>The password for the master user of the database.</p>
    pub fn master_user_password(&self) -> ::std::option::Option<&str> {
        self.master_user_password.as_deref()
    }
    /// <p>The database engine version.</p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>A Boolean value indicating whether automated backup retention is enabled.</p>
    pub fn backup_retention_enabled(&self) -> ::std::option::Option<bool> {
        self.backup_retention_enabled
    }
}
impl PendingModifiedRelationalDatabaseValues {
    /// Creates a new builder-style object to manufacture [`PendingModifiedRelationalDatabaseValues`](crate::types::PendingModifiedRelationalDatabaseValues).
    pub fn builder() -> crate::types::builders::PendingModifiedRelationalDatabaseValuesBuilder {
        crate::types::builders::PendingModifiedRelationalDatabaseValuesBuilder::default()
    }
}

/// A builder for [`PendingModifiedRelationalDatabaseValues`](crate::types::PendingModifiedRelationalDatabaseValues).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PendingModifiedRelationalDatabaseValuesBuilder {
    pub(crate) master_user_password: ::std::option::Option<::std::string::String>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) backup_retention_enabled: ::std::option::Option<bool>,
}
impl PendingModifiedRelationalDatabaseValuesBuilder {
    /// <p>The password for the master user of the database.</p>
    pub fn master_user_password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password for the master user of the database.</p>
    pub fn set_master_user_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_password = input;
        self
    }
    /// <p>The password for the master user of the database.</p>
    pub fn get_master_user_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_password
    }
    /// <p>The database engine version.</p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database engine version.</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The database engine version.</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>A Boolean value indicating whether automated backup retention is enabled.</p>
    pub fn backup_retention_enabled(mut self, input: bool) -> Self {
        self.backup_retention_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value indicating whether automated backup retention is enabled.</p>
    pub fn set_backup_retention_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.backup_retention_enabled = input;
        self
    }
    /// <p>A Boolean value indicating whether automated backup retention is enabled.</p>
    pub fn get_backup_retention_enabled(&self) -> &::std::option::Option<bool> {
        &self.backup_retention_enabled
    }
    /// Consumes the builder and constructs a [`PendingModifiedRelationalDatabaseValues`](crate::types::PendingModifiedRelationalDatabaseValues).
    pub fn build(self) -> crate::types::PendingModifiedRelationalDatabaseValues {
        crate::types::PendingModifiedRelationalDatabaseValues {
            master_user_password: self.master_user_password,
            engine_version: self.engine_version,
            backup_retention_enabled: self.backup_retention_enabled,
        }
    }
}
