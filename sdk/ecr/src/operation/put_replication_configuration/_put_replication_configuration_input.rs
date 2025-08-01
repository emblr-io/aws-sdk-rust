// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutReplicationConfigurationInput {
    /// <p>An object representing the replication configuration for a registry.</p>
    pub replication_configuration: ::std::option::Option<crate::types::ReplicationConfiguration>,
}
impl PutReplicationConfigurationInput {
    /// <p>An object representing the replication configuration for a registry.</p>
    pub fn replication_configuration(&self) -> ::std::option::Option<&crate::types::ReplicationConfiguration> {
        self.replication_configuration.as_ref()
    }
}
impl PutReplicationConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutReplicationConfigurationInput`](crate::operation::put_replication_configuration::PutReplicationConfigurationInput).
    pub fn builder() -> crate::operation::put_replication_configuration::builders::PutReplicationConfigurationInputBuilder {
        crate::operation::put_replication_configuration::builders::PutReplicationConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutReplicationConfigurationInput`](crate::operation::put_replication_configuration::PutReplicationConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutReplicationConfigurationInputBuilder {
    pub(crate) replication_configuration: ::std::option::Option<crate::types::ReplicationConfiguration>,
}
impl PutReplicationConfigurationInputBuilder {
    /// <p>An object representing the replication configuration for a registry.</p>
    /// This field is required.
    pub fn replication_configuration(mut self, input: crate::types::ReplicationConfiguration) -> Self {
        self.replication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object representing the replication configuration for a registry.</p>
    pub fn set_replication_configuration(mut self, input: ::std::option::Option<crate::types::ReplicationConfiguration>) -> Self {
        self.replication_configuration = input;
        self
    }
    /// <p>An object representing the replication configuration for a registry.</p>
    pub fn get_replication_configuration(&self) -> &::std::option::Option<crate::types::ReplicationConfiguration> {
        &self.replication_configuration
    }
    /// Consumes the builder and constructs a [`PutReplicationConfigurationInput`](crate::operation::put_replication_configuration::PutReplicationConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_replication_configuration::PutReplicationConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_replication_configuration::PutReplicationConfigurationInput {
            replication_configuration: self.replication_configuration,
        })
    }
}
