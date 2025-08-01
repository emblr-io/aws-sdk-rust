// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Preferences on managing your databases on AWS.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DatabasePreferences {
    /// <p>Specifies whether you're interested in self-managed databases or databases managed by AWS.</p>
    pub database_management_preference: ::std::option::Option<crate::types::DatabaseManagementPreference>,
    /// <p>Specifies your preferred migration path.</p>
    pub database_migration_preference: ::std::option::Option<crate::types::DatabaseMigrationPreference>,
}
impl DatabasePreferences {
    /// <p>Specifies whether you're interested in self-managed databases or databases managed by AWS.</p>
    pub fn database_management_preference(&self) -> ::std::option::Option<&crate::types::DatabaseManagementPreference> {
        self.database_management_preference.as_ref()
    }
    /// <p>Specifies your preferred migration path.</p>
    pub fn database_migration_preference(&self) -> ::std::option::Option<&crate::types::DatabaseMigrationPreference> {
        self.database_migration_preference.as_ref()
    }
}
impl DatabasePreferences {
    /// Creates a new builder-style object to manufacture [`DatabasePreferences`](crate::types::DatabasePreferences).
    pub fn builder() -> crate::types::builders::DatabasePreferencesBuilder {
        crate::types::builders::DatabasePreferencesBuilder::default()
    }
}

/// A builder for [`DatabasePreferences`](crate::types::DatabasePreferences).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatabasePreferencesBuilder {
    pub(crate) database_management_preference: ::std::option::Option<crate::types::DatabaseManagementPreference>,
    pub(crate) database_migration_preference: ::std::option::Option<crate::types::DatabaseMigrationPreference>,
}
impl DatabasePreferencesBuilder {
    /// <p>Specifies whether you're interested in self-managed databases or databases managed by AWS.</p>
    pub fn database_management_preference(mut self, input: crate::types::DatabaseManagementPreference) -> Self {
        self.database_management_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether you're interested in self-managed databases or databases managed by AWS.</p>
    pub fn set_database_management_preference(mut self, input: ::std::option::Option<crate::types::DatabaseManagementPreference>) -> Self {
        self.database_management_preference = input;
        self
    }
    /// <p>Specifies whether you're interested in self-managed databases or databases managed by AWS.</p>
    pub fn get_database_management_preference(&self) -> &::std::option::Option<crate::types::DatabaseManagementPreference> {
        &self.database_management_preference
    }
    /// <p>Specifies your preferred migration path.</p>
    pub fn database_migration_preference(mut self, input: crate::types::DatabaseMigrationPreference) -> Self {
        self.database_migration_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies your preferred migration path.</p>
    pub fn set_database_migration_preference(mut self, input: ::std::option::Option<crate::types::DatabaseMigrationPreference>) -> Self {
        self.database_migration_preference = input;
        self
    }
    /// <p>Specifies your preferred migration path.</p>
    pub fn get_database_migration_preference(&self) -> &::std::option::Option<crate::types::DatabaseMigrationPreference> {
        &self.database_migration_preference
    }
    /// Consumes the builder and constructs a [`DatabasePreferences`](crate::types::DatabasePreferences).
    pub fn build(self) -> crate::types::DatabasePreferences {
        crate::types::DatabasePreferences {
            database_management_preference: self.database_management_preference,
            database_migration_preference: self.database_migration_preference,
        }
    }
}
