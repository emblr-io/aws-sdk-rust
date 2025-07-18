// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a summary of a DB instance belonging to a DB cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbInstanceForClusterSummary {
    /// <p>The service-generated unique identifier of the DB instance.</p>
    pub id: ::std::string::String,
    /// <p>A service-generated name for the DB instance based on the customer-supplied name for the DB cluster.</p>
    pub name: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the DB instance.</p>
    pub arn: ::std::string::String,
    /// <p>The status of the DB instance.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>The endpoint used to connect to InfluxDB. The default InfluxDB port is 8086.</p>
    pub endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The port number on which InfluxDB accepts connections.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>Specifies whether the network type of the Timestream for InfluxDB instance is IPv4, which can communicate over IPv4 protocol only, or DUAL, which can communicate over both IPv4 and IPv6 protocols.</p>
    pub network_type: ::std::option::Option<crate::types::NetworkType>,
    /// <p>The Timestream for InfluxDB instance type to run InfluxDB on.</p>
    pub db_instance_type: ::std::option::Option<crate::types::DbInstanceType>,
    /// <p>The storage type for your DB instance.</p>
    pub db_storage_type: ::std::option::Option<crate::types::DbStorageType>,
    /// <p>The amount of storage allocated for your DB storage type in GiB (gibibytes).</p>
    pub allocated_storage: ::std::option::Option<i32>,
    /// <p>Specifies the deployment type if applicable.</p>
    pub deployment_type: ::std::option::Option<crate::types::DeploymentType>,
    /// <p>Specifies the DB instance's role in the cluster.</p>
    pub instance_mode: ::std::option::Option<crate::types::InstanceMode>,
}
impl DbInstanceForClusterSummary {
    /// <p>The service-generated unique identifier of the DB instance.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>A service-generated name for the DB instance based on the customer-supplied name for the DB cluster.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the DB instance.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The status of the DB instance.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>The endpoint used to connect to InfluxDB. The default InfluxDB port is 8086.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&str> {
        self.endpoint.as_deref()
    }
    /// <p>The port number on which InfluxDB accepts connections.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>Specifies whether the network type of the Timestream for InfluxDB instance is IPv4, which can communicate over IPv4 protocol only, or DUAL, which can communicate over both IPv4 and IPv6 protocols.</p>
    pub fn network_type(&self) -> ::std::option::Option<&crate::types::NetworkType> {
        self.network_type.as_ref()
    }
    /// <p>The Timestream for InfluxDB instance type to run InfluxDB on.</p>
    pub fn db_instance_type(&self) -> ::std::option::Option<&crate::types::DbInstanceType> {
        self.db_instance_type.as_ref()
    }
    /// <p>The storage type for your DB instance.</p>
    pub fn db_storage_type(&self) -> ::std::option::Option<&crate::types::DbStorageType> {
        self.db_storage_type.as_ref()
    }
    /// <p>The amount of storage allocated for your DB storage type in GiB (gibibytes).</p>
    pub fn allocated_storage(&self) -> ::std::option::Option<i32> {
        self.allocated_storage
    }
    /// <p>Specifies the deployment type if applicable.</p>
    pub fn deployment_type(&self) -> ::std::option::Option<&crate::types::DeploymentType> {
        self.deployment_type.as_ref()
    }
    /// <p>Specifies the DB instance's role in the cluster.</p>
    pub fn instance_mode(&self) -> ::std::option::Option<&crate::types::InstanceMode> {
        self.instance_mode.as_ref()
    }
}
impl DbInstanceForClusterSummary {
    /// Creates a new builder-style object to manufacture [`DbInstanceForClusterSummary`](crate::types::DbInstanceForClusterSummary).
    pub fn builder() -> crate::types::builders::DbInstanceForClusterSummaryBuilder {
        crate::types::builders::DbInstanceForClusterSummaryBuilder::default()
    }
}

/// A builder for [`DbInstanceForClusterSummary`](crate::types::DbInstanceForClusterSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbInstanceForClusterSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) network_type: ::std::option::Option<crate::types::NetworkType>,
    pub(crate) db_instance_type: ::std::option::Option<crate::types::DbInstanceType>,
    pub(crate) db_storage_type: ::std::option::Option<crate::types::DbStorageType>,
    pub(crate) allocated_storage: ::std::option::Option<i32>,
    pub(crate) deployment_type: ::std::option::Option<crate::types::DeploymentType>,
    pub(crate) instance_mode: ::std::option::Option<crate::types::InstanceMode>,
}
impl DbInstanceForClusterSummaryBuilder {
    /// <p>The service-generated unique identifier of the DB instance.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service-generated unique identifier of the DB instance.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The service-generated unique identifier of the DB instance.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A service-generated name for the DB instance based on the customer-supplied name for the DB cluster.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A service-generated name for the DB instance based on the customer-supplied name for the DB cluster.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A service-generated name for the DB instance based on the customer-supplied name for the DB cluster.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the DB instance.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the DB instance.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the DB instance.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The status of the DB instance.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the DB instance.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the DB instance.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>The endpoint used to connect to InfluxDB. The default InfluxDB port is 8086.</p>
    pub fn endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint used to connect to InfluxDB. The default InfluxDB port is 8086.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The endpoint used to connect to InfluxDB. The default InfluxDB port is 8086.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint
    }
    /// <p>The port number on which InfluxDB accepts connections.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number on which InfluxDB accepts connections.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port number on which InfluxDB accepts connections.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>Specifies whether the network type of the Timestream for InfluxDB instance is IPv4, which can communicate over IPv4 protocol only, or DUAL, which can communicate over both IPv4 and IPv6 protocols.</p>
    pub fn network_type(mut self, input: crate::types::NetworkType) -> Self {
        self.network_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the network type of the Timestream for InfluxDB instance is IPv4, which can communicate over IPv4 protocol only, or DUAL, which can communicate over both IPv4 and IPv6 protocols.</p>
    pub fn set_network_type(mut self, input: ::std::option::Option<crate::types::NetworkType>) -> Self {
        self.network_type = input;
        self
    }
    /// <p>Specifies whether the network type of the Timestream for InfluxDB instance is IPv4, which can communicate over IPv4 protocol only, or DUAL, which can communicate over both IPv4 and IPv6 protocols.</p>
    pub fn get_network_type(&self) -> &::std::option::Option<crate::types::NetworkType> {
        &self.network_type
    }
    /// <p>The Timestream for InfluxDB instance type to run InfluxDB on.</p>
    pub fn db_instance_type(mut self, input: crate::types::DbInstanceType) -> Self {
        self.db_instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Timestream for InfluxDB instance type to run InfluxDB on.</p>
    pub fn set_db_instance_type(mut self, input: ::std::option::Option<crate::types::DbInstanceType>) -> Self {
        self.db_instance_type = input;
        self
    }
    /// <p>The Timestream for InfluxDB instance type to run InfluxDB on.</p>
    pub fn get_db_instance_type(&self) -> &::std::option::Option<crate::types::DbInstanceType> {
        &self.db_instance_type
    }
    /// <p>The storage type for your DB instance.</p>
    pub fn db_storage_type(mut self, input: crate::types::DbStorageType) -> Self {
        self.db_storage_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage type for your DB instance.</p>
    pub fn set_db_storage_type(mut self, input: ::std::option::Option<crate::types::DbStorageType>) -> Self {
        self.db_storage_type = input;
        self
    }
    /// <p>The storage type for your DB instance.</p>
    pub fn get_db_storage_type(&self) -> &::std::option::Option<crate::types::DbStorageType> {
        &self.db_storage_type
    }
    /// <p>The amount of storage allocated for your DB storage type in GiB (gibibytes).</p>
    pub fn allocated_storage(mut self, input: i32) -> Self {
        self.allocated_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of storage allocated for your DB storage type in GiB (gibibytes).</p>
    pub fn set_allocated_storage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.allocated_storage = input;
        self
    }
    /// <p>The amount of storage allocated for your DB storage type in GiB (gibibytes).</p>
    pub fn get_allocated_storage(&self) -> &::std::option::Option<i32> {
        &self.allocated_storage
    }
    /// <p>Specifies the deployment type if applicable.</p>
    pub fn deployment_type(mut self, input: crate::types::DeploymentType) -> Self {
        self.deployment_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the deployment type if applicable.</p>
    pub fn set_deployment_type(mut self, input: ::std::option::Option<crate::types::DeploymentType>) -> Self {
        self.deployment_type = input;
        self
    }
    /// <p>Specifies the deployment type if applicable.</p>
    pub fn get_deployment_type(&self) -> &::std::option::Option<crate::types::DeploymentType> {
        &self.deployment_type
    }
    /// <p>Specifies the DB instance's role in the cluster.</p>
    pub fn instance_mode(mut self, input: crate::types::InstanceMode) -> Self {
        self.instance_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the DB instance's role in the cluster.</p>
    pub fn set_instance_mode(mut self, input: ::std::option::Option<crate::types::InstanceMode>) -> Self {
        self.instance_mode = input;
        self
    }
    /// <p>Specifies the DB instance's role in the cluster.</p>
    pub fn get_instance_mode(&self) -> &::std::option::Option<crate::types::InstanceMode> {
        &self.instance_mode
    }
    /// Consumes the builder and constructs a [`DbInstanceForClusterSummary`](crate::types::DbInstanceForClusterSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::DbInstanceForClusterSummaryBuilder::id)
    /// - [`name`](crate::types::builders::DbInstanceForClusterSummaryBuilder::name)
    /// - [`arn`](crate::types::builders::DbInstanceForClusterSummaryBuilder::arn)
    pub fn build(self) -> ::std::result::Result<crate::types::DbInstanceForClusterSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DbInstanceForClusterSummary {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building DbInstanceForClusterSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DbInstanceForClusterSummary",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building DbInstanceForClusterSummary",
                )
            })?,
            status: self.status,
            endpoint: self.endpoint,
            port: self.port,
            network_type: self.network_type,
            db_instance_type: self.db_instance_type,
            db_storage_type: self.db_storage_type,
            allocated_storage: self.allocated_storage,
            deployment_type: self.deployment_type,
            instance_mode: self.instance_mode,
        })
    }
}
