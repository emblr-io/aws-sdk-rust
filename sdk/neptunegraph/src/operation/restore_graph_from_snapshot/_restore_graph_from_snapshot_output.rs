// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreGraphFromSnapshotOutput {
    /// <p>The unique identifier of the graph.</p>
    pub id: ::std::string::String,
    /// <p>The name of the graph.</p>
    pub name: ::std::string::String,
    /// <p>The ARN associated with the graph.</p>
    pub arn: ::std::string::String,
    /// <p>The status of the graph.</p>
    pub status: ::std::option::Option<crate::types::GraphStatus>,
    /// <p>The reason that the graph has this status.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the graph was created.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of memory-optimized Neptune Capacity Units (m-NCUs) allocated to the graph.</p>
    pub provisioned_memory: ::std::option::Option<i32>,
    /// <p>The graph endpoint.</p>
    pub endpoint: ::std::option::Option<::std::string::String>,
    /// <p>If <code>true</code>, the graph has a public endpoint, otherwise not.</p>
    pub public_connectivity: ::std::option::Option<bool>,
    /// <p>Specifies the number of dimensions for vector embeddings loaded into the graph. Max = 65535</p>
    pub vector_search_configuration: ::std::option::Option<crate::types::VectorSearchConfiguration>,
    /// <p>The number of replicas for the graph.</p>
    pub replica_count: ::std::option::Option<i32>,
    /// <p>The ID of the KMS key used to encrypt and decrypt graph data.</p>
    pub kms_key_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the snapshot from which the graph was created, if any.</p>
    pub source_snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>If <code>true</code>, deletion protection is enabled for the graph.</p>
    pub deletion_protection: ::std::option::Option<bool>,
    /// <p>The build number of the graph.</p>
    pub build_number: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RestoreGraphFromSnapshotOutput {
    /// <p>The unique identifier of the graph.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the graph.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The ARN associated with the graph.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The status of the graph.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::GraphStatus> {
        self.status.as_ref()
    }
    /// <p>The reason that the graph has this status.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
    /// <p>The time at which the graph was created.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>The number of memory-optimized Neptune Capacity Units (m-NCUs) allocated to the graph.</p>
    pub fn provisioned_memory(&self) -> ::std::option::Option<i32> {
        self.provisioned_memory
    }
    /// <p>The graph endpoint.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&str> {
        self.endpoint.as_deref()
    }
    /// <p>If <code>true</code>, the graph has a public endpoint, otherwise not.</p>
    pub fn public_connectivity(&self) -> ::std::option::Option<bool> {
        self.public_connectivity
    }
    /// <p>Specifies the number of dimensions for vector embeddings loaded into the graph. Max = 65535</p>
    pub fn vector_search_configuration(&self) -> ::std::option::Option<&crate::types::VectorSearchConfiguration> {
        self.vector_search_configuration.as_ref()
    }
    /// <p>The number of replicas for the graph.</p>
    pub fn replica_count(&self) -> ::std::option::Option<i32> {
        self.replica_count
    }
    /// <p>The ID of the KMS key used to encrypt and decrypt graph data.</p>
    pub fn kms_key_identifier(&self) -> ::std::option::Option<&str> {
        self.kms_key_identifier.as_deref()
    }
    /// <p>The ID of the snapshot from which the graph was created, if any.</p>
    pub fn source_snapshot_id(&self) -> ::std::option::Option<&str> {
        self.source_snapshot_id.as_deref()
    }
    /// <p>If <code>true</code>, deletion protection is enabled for the graph.</p>
    pub fn deletion_protection(&self) -> ::std::option::Option<bool> {
        self.deletion_protection
    }
    /// <p>The build number of the graph.</p>
    pub fn build_number(&self) -> ::std::option::Option<&str> {
        self.build_number.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for RestoreGraphFromSnapshotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RestoreGraphFromSnapshotOutput {
    /// Creates a new builder-style object to manufacture [`RestoreGraphFromSnapshotOutput`](crate::operation::restore_graph_from_snapshot::RestoreGraphFromSnapshotOutput).
    pub fn builder() -> crate::operation::restore_graph_from_snapshot::builders::RestoreGraphFromSnapshotOutputBuilder {
        crate::operation::restore_graph_from_snapshot::builders::RestoreGraphFromSnapshotOutputBuilder::default()
    }
}

/// A builder for [`RestoreGraphFromSnapshotOutput`](crate::operation::restore_graph_from_snapshot::RestoreGraphFromSnapshotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreGraphFromSnapshotOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::GraphStatus>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) provisioned_memory: ::std::option::Option<i32>,
    pub(crate) endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) public_connectivity: ::std::option::Option<bool>,
    pub(crate) vector_search_configuration: ::std::option::Option<crate::types::VectorSearchConfiguration>,
    pub(crate) replica_count: ::std::option::Option<i32>,
    pub(crate) kms_key_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) source_snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) deletion_protection: ::std::option::Option<bool>,
    pub(crate) build_number: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RestoreGraphFromSnapshotOutputBuilder {
    /// <p>The unique identifier of the graph.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the graph.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the graph.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the graph.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the graph.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the graph.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN associated with the graph.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN associated with the graph.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN associated with the graph.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The status of the graph.</p>
    pub fn status(mut self, input: crate::types::GraphStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the graph.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::GraphStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the graph.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::GraphStatus> {
        &self.status
    }
    /// <p>The reason that the graph has this status.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason that the graph has this status.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The reason that the graph has this status.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// <p>The time at which the graph was created.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the graph was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time at which the graph was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The number of memory-optimized Neptune Capacity Units (m-NCUs) allocated to the graph.</p>
    pub fn provisioned_memory(mut self, input: i32) -> Self {
        self.provisioned_memory = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of memory-optimized Neptune Capacity Units (m-NCUs) allocated to the graph.</p>
    pub fn set_provisioned_memory(mut self, input: ::std::option::Option<i32>) -> Self {
        self.provisioned_memory = input;
        self
    }
    /// <p>The number of memory-optimized Neptune Capacity Units (m-NCUs) allocated to the graph.</p>
    pub fn get_provisioned_memory(&self) -> &::std::option::Option<i32> {
        &self.provisioned_memory
    }
    /// <p>The graph endpoint.</p>
    pub fn endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The graph endpoint.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The graph endpoint.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint
    }
    /// <p>If <code>true</code>, the graph has a public endpoint, otherwise not.</p>
    pub fn public_connectivity(mut self, input: bool) -> Self {
        self.public_connectivity = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>true</code>, the graph has a public endpoint, otherwise not.</p>
    pub fn set_public_connectivity(mut self, input: ::std::option::Option<bool>) -> Self {
        self.public_connectivity = input;
        self
    }
    /// <p>If <code>true</code>, the graph has a public endpoint, otherwise not.</p>
    pub fn get_public_connectivity(&self) -> &::std::option::Option<bool> {
        &self.public_connectivity
    }
    /// <p>Specifies the number of dimensions for vector embeddings loaded into the graph. Max = 65535</p>
    pub fn vector_search_configuration(mut self, input: crate::types::VectorSearchConfiguration) -> Self {
        self.vector_search_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the number of dimensions for vector embeddings loaded into the graph. Max = 65535</p>
    pub fn set_vector_search_configuration(mut self, input: ::std::option::Option<crate::types::VectorSearchConfiguration>) -> Self {
        self.vector_search_configuration = input;
        self
    }
    /// <p>Specifies the number of dimensions for vector embeddings loaded into the graph. Max = 65535</p>
    pub fn get_vector_search_configuration(&self) -> &::std::option::Option<crate::types::VectorSearchConfiguration> {
        &self.vector_search_configuration
    }
    /// <p>The number of replicas for the graph.</p>
    pub fn replica_count(mut self, input: i32) -> Self {
        self.replica_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of replicas for the graph.</p>
    pub fn set_replica_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.replica_count = input;
        self
    }
    /// <p>The number of replicas for the graph.</p>
    pub fn get_replica_count(&self) -> &::std::option::Option<i32> {
        &self.replica_count
    }
    /// <p>The ID of the KMS key used to encrypt and decrypt graph data.</p>
    pub fn kms_key_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the KMS key used to encrypt and decrypt graph data.</p>
    pub fn set_kms_key_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_identifier = input;
        self
    }
    /// <p>The ID of the KMS key used to encrypt and decrypt graph data.</p>
    pub fn get_kms_key_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_identifier
    }
    /// <p>The ID of the snapshot from which the graph was created, if any.</p>
    pub fn source_snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the snapshot from which the graph was created, if any.</p>
    pub fn set_source_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_snapshot_id = input;
        self
    }
    /// <p>The ID of the snapshot from which the graph was created, if any.</p>
    pub fn get_source_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_snapshot_id
    }
    /// <p>If <code>true</code>, deletion protection is enabled for the graph.</p>
    pub fn deletion_protection(mut self, input: bool) -> Self {
        self.deletion_protection = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>true</code>, deletion protection is enabled for the graph.</p>
    pub fn set_deletion_protection(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deletion_protection = input;
        self
    }
    /// <p>If <code>true</code>, deletion protection is enabled for the graph.</p>
    pub fn get_deletion_protection(&self) -> &::std::option::Option<bool> {
        &self.deletion_protection
    }
    /// <p>The build number of the graph.</p>
    pub fn build_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.build_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The build number of the graph.</p>
    pub fn set_build_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.build_number = input;
        self
    }
    /// <p>The build number of the graph.</p>
    pub fn get_build_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.build_number
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RestoreGraphFromSnapshotOutput`](crate::operation::restore_graph_from_snapshot::RestoreGraphFromSnapshotOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::restore_graph_from_snapshot::builders::RestoreGraphFromSnapshotOutputBuilder::id)
    /// - [`name`](crate::operation::restore_graph_from_snapshot::builders::RestoreGraphFromSnapshotOutputBuilder::name)
    /// - [`arn`](crate::operation::restore_graph_from_snapshot::builders::RestoreGraphFromSnapshotOutputBuilder::arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::restore_graph_from_snapshot::RestoreGraphFromSnapshotOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::restore_graph_from_snapshot::RestoreGraphFromSnapshotOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building RestoreGraphFromSnapshotOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building RestoreGraphFromSnapshotOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building RestoreGraphFromSnapshotOutput",
                )
            })?,
            status: self.status,
            status_reason: self.status_reason,
            create_time: self.create_time,
            provisioned_memory: self.provisioned_memory,
            endpoint: self.endpoint,
            public_connectivity: self.public_connectivity,
            vector_search_configuration: self.vector_search_configuration,
            replica_count: self.replica_count,
            kms_key_identifier: self.kms_key_identifier,
            source_snapshot_id: self.source_snapshot_id,
            deletion_protection: self.deletion_protection,
            build_number: self.build_number,
            _request_id: self._request_id,
        })
    }
}
