// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the properties of the related standby WorkSpaces.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StandbyWorkspacesProperties {
    /// <p>The identifier of the standby WorkSpace</p>
    pub standby_workspace_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether data replication is enabled, and if enabled, the type of data replication.</p>
    pub data_replication: ::std::option::Option<crate::types::DataReplication>,
    /// <p>The date and time at which the last successful snapshot was taken of the primary WorkSpace used for replicating data.</p>
    pub recovery_snapshot_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl StandbyWorkspacesProperties {
    /// <p>The identifier of the standby WorkSpace</p>
    pub fn standby_workspace_id(&self) -> ::std::option::Option<&str> {
        self.standby_workspace_id.as_deref()
    }
    /// <p>Indicates whether data replication is enabled, and if enabled, the type of data replication.</p>
    pub fn data_replication(&self) -> ::std::option::Option<&crate::types::DataReplication> {
        self.data_replication.as_ref()
    }
    /// <p>The date and time at which the last successful snapshot was taken of the primary WorkSpace used for replicating data.</p>
    pub fn recovery_snapshot_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.recovery_snapshot_time.as_ref()
    }
}
impl StandbyWorkspacesProperties {
    /// Creates a new builder-style object to manufacture [`StandbyWorkspacesProperties`](crate::types::StandbyWorkspacesProperties).
    pub fn builder() -> crate::types::builders::StandbyWorkspacesPropertiesBuilder {
        crate::types::builders::StandbyWorkspacesPropertiesBuilder::default()
    }
}

/// A builder for [`StandbyWorkspacesProperties`](crate::types::StandbyWorkspacesProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StandbyWorkspacesPropertiesBuilder {
    pub(crate) standby_workspace_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_replication: ::std::option::Option<crate::types::DataReplication>,
    pub(crate) recovery_snapshot_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl StandbyWorkspacesPropertiesBuilder {
    /// <p>The identifier of the standby WorkSpace</p>
    pub fn standby_workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.standby_workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the standby WorkSpace</p>
    pub fn set_standby_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.standby_workspace_id = input;
        self
    }
    /// <p>The identifier of the standby WorkSpace</p>
    pub fn get_standby_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.standby_workspace_id
    }
    /// <p>Indicates whether data replication is enabled, and if enabled, the type of data replication.</p>
    pub fn data_replication(mut self, input: crate::types::DataReplication) -> Self {
        self.data_replication = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether data replication is enabled, and if enabled, the type of data replication.</p>
    pub fn set_data_replication(mut self, input: ::std::option::Option<crate::types::DataReplication>) -> Self {
        self.data_replication = input;
        self
    }
    /// <p>Indicates whether data replication is enabled, and if enabled, the type of data replication.</p>
    pub fn get_data_replication(&self) -> &::std::option::Option<crate::types::DataReplication> {
        &self.data_replication
    }
    /// <p>The date and time at which the last successful snapshot was taken of the primary WorkSpace used for replicating data.</p>
    pub fn recovery_snapshot_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.recovery_snapshot_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the last successful snapshot was taken of the primary WorkSpace used for replicating data.</p>
    pub fn set_recovery_snapshot_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.recovery_snapshot_time = input;
        self
    }
    /// <p>The date and time at which the last successful snapshot was taken of the primary WorkSpace used for replicating data.</p>
    pub fn get_recovery_snapshot_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.recovery_snapshot_time
    }
    /// Consumes the builder and constructs a [`StandbyWorkspacesProperties`](crate::types::StandbyWorkspacesProperties).
    pub fn build(self) -> crate::types::StandbyWorkspacesProperties {
        crate::types::StandbyWorkspacesProperties {
            standby_workspace_id: self.standby_workspace_id,
            data_replication: self.data_replication,
            recovery_snapshot_time: self.recovery_snapshot_time,
        }
    }
}
