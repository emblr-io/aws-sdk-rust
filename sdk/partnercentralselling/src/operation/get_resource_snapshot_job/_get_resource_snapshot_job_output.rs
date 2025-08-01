// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceSnapshotJobOutput {
    /// <p>The catalog in which the snapshot job was created. This will match the Catalog specified in the request.</p>
    pub catalog: ::std::string::String,
    /// <p>The unique identifier of the snapshot job. This matches the ResourceSnapshotJobIdentifier provided in the request.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the snapshot job. This globally unique identifier can be used for resource-specific operations across AWS services.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the engagement associated with this snapshot job. This links the job to a specific engagement context.</p>
    pub engagement_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of resource being snapshotted. This would have "Opportunity" as a value as it is dependent on the supported resource type.</p>
    pub resource_type: ::std::option::Option<crate::types::ResourceType>,
    /// <p>The identifier of the specific resource being snapshotted. The format might vary depending on the ResourceType.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the resource being snapshotted. This provides a globally unique identifier for the resource across AWS.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the template used for creating the snapshot. This is the same as the template name. It defines the structure and content of the snapshot.</p>
    pub resource_snapshot_template_name: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the snapshot job was created in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current status of the snapshot job. Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
    /// <p>The date and time of the last successful execution of the job, in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub last_successful_execution_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>If the job has encountered any failures, this field contains the error message from the most recent failure. This can be useful for troubleshooting issues with the job.</p>
    pub last_failure: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourceSnapshotJobOutput {
    /// <p>The catalog in which the snapshot job was created. This will match the Catalog specified in the request.</p>
    pub fn catalog(&self) -> &str {
        use std::ops::Deref;
        self.catalog.deref()
    }
    /// <p>The unique identifier of the snapshot job. This matches the ResourceSnapshotJobIdentifier provided in the request.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot job. This globally unique identifier can be used for resource-specific operations across AWS services.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The identifier of the engagement associated with this snapshot job. This links the job to a specific engagement context.</p>
    pub fn engagement_id(&self) -> ::std::option::Option<&str> {
        self.engagement_id.as_deref()
    }
    /// <p>The type of resource being snapshotted. This would have "Opportunity" as a value as it is dependent on the supported resource type.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The identifier of the specific resource being snapshotted. The format might vary depending on the ResourceType.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource being snapshotted. This provides a globally unique identifier for the resource across AWS.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The name of the template used for creating the snapshot. This is the same as the template name. It defines the structure and content of the snapshot.</p>
    pub fn resource_snapshot_template_name(&self) -> ::std::option::Option<&str> {
        self.resource_snapshot_template_name.as_deref()
    }
    /// <p>The date and time when the snapshot job was created in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The current status of the snapshot job. Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceSnapshotJobStatus> {
        self.status.as_ref()
    }
    /// <p>The date and time of the last successful execution of the job, in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn last_successful_execution_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_successful_execution_date.as_ref()
    }
    /// <p>If the job has encountered any failures, this field contains the error message from the most recent failure. This can be useful for troubleshooting issues with the job.</p>
    pub fn last_failure(&self) -> ::std::option::Option<&str> {
        self.last_failure.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourceSnapshotJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourceSnapshotJobOutput {
    /// Creates a new builder-style object to manufacture [`GetResourceSnapshotJobOutput`](crate::operation::get_resource_snapshot_job::GetResourceSnapshotJobOutput).
    pub fn builder() -> crate::operation::get_resource_snapshot_job::builders::GetResourceSnapshotJobOutputBuilder {
        crate::operation::get_resource_snapshot_job::builders::GetResourceSnapshotJobOutputBuilder::default()
    }
}

/// A builder for [`GetResourceSnapshotJobOutput`](crate::operation::get_resource_snapshot_job::GetResourceSnapshotJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceSnapshotJobOutputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) engagement_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_snapshot_template_name: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
    pub(crate) last_successful_execution_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_failure: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourceSnapshotJobOutputBuilder {
    /// <p>The catalog in which the snapshot job was created. This will match the Catalog specified in the request.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The catalog in which the snapshot job was created. This will match the Catalog specified in the request.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>The catalog in which the snapshot job was created. This will match the Catalog specified in the request.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>The unique identifier of the snapshot job. This matches the ResourceSnapshotJobIdentifier provided in the request.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the snapshot job. This matches the ResourceSnapshotJobIdentifier provided in the request.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the snapshot job. This matches the ResourceSnapshotJobIdentifier provided in the request.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot job. This globally unique identifier can be used for resource-specific operations across AWS services.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot job. This globally unique identifier can be used for resource-specific operations across AWS services.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot job. This globally unique identifier can be used for resource-specific operations across AWS services.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The identifier of the engagement associated with this snapshot job. This links the job to a specific engagement context.</p>
    pub fn engagement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engagement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the engagement associated with this snapshot job. This links the job to a specific engagement context.</p>
    pub fn set_engagement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engagement_id = input;
        self
    }
    /// <p>The identifier of the engagement associated with this snapshot job. This links the job to a specific engagement context.</p>
    pub fn get_engagement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.engagement_id
    }
    /// <p>The type of resource being snapshotted. This would have "Opportunity" as a value as it is dependent on the supported resource type.</p>
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource being snapshotted. This would have "Opportunity" as a value as it is dependent on the supported resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of resource being snapshotted. This would have "Opportunity" as a value as it is dependent on the supported resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// <p>The identifier of the specific resource being snapshotted. The format might vary depending on the ResourceType.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the specific resource being snapshotted. The format might vary depending on the ResourceType.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The identifier of the specific resource being snapshotted. The format might vary depending on the ResourceType.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The Amazon Resource Name (ARN) of the resource being snapshotted. This provides a globally unique identifier for the resource across AWS.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource being snapshotted. This provides a globally unique identifier for the resource across AWS.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource being snapshotted. This provides a globally unique identifier for the resource across AWS.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The name of the template used for creating the snapshot. This is the same as the template name. It defines the structure and content of the snapshot.</p>
    pub fn resource_snapshot_template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_snapshot_template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the template used for creating the snapshot. This is the same as the template name. It defines the structure and content of the snapshot.</p>
    pub fn set_resource_snapshot_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_snapshot_template_name = input;
        self
    }
    /// <p>The name of the template used for creating the snapshot. This is the same as the template name. It defines the structure and content of the snapshot.</p>
    pub fn get_resource_snapshot_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_snapshot_template_name
    }
    /// <p>The date and time when the snapshot job was created in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the snapshot job was created in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time when the snapshot job was created in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The current status of the snapshot job. Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::ResourceSnapshotJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the snapshot job. Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the snapshot job. Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceSnapshotJobStatus> {
        &self.status
    }
    /// <p>The date and time of the last successful execution of the job, in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn last_successful_execution_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_successful_execution_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time of the last successful execution of the job, in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn set_last_successful_execution_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_successful_execution_date = input;
        self
    }
    /// <p>The date and time of the last successful execution of the job, in ISO 8601 format (UTC). Example: "2023-05-01T20:37:46Z"</p>
    pub fn get_last_successful_execution_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_successful_execution_date
    }
    /// <p>If the job has encountered any failures, this field contains the error message from the most recent failure. This can be useful for troubleshooting issues with the job.</p>
    pub fn last_failure(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_failure = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the job has encountered any failures, this field contains the error message from the most recent failure. This can be useful for troubleshooting issues with the job.</p>
    pub fn set_last_failure(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_failure = input;
        self
    }
    /// <p>If the job has encountered any failures, this field contains the error message from the most recent failure. This can be useful for troubleshooting issues with the job.</p>
    pub fn get_last_failure(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_failure
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetResourceSnapshotJobOutput`](crate::operation::get_resource_snapshot_job::GetResourceSnapshotJobOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`catalog`](crate::operation::get_resource_snapshot_job::builders::GetResourceSnapshotJobOutputBuilder::catalog)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_resource_snapshot_job::GetResourceSnapshotJobOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_resource_snapshot_job::GetResourceSnapshotJobOutput {
            catalog: self.catalog.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "catalog",
                    "catalog was not specified but it is required when building GetResourceSnapshotJobOutput",
                )
            })?,
            id: self.id,
            arn: self.arn,
            engagement_id: self.engagement_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            resource_arn: self.resource_arn,
            resource_snapshot_template_name: self.resource_snapshot_template_name,
            created_at: self.created_at,
            status: self.status,
            last_successful_execution_date: self.last_successful_execution_date,
            last_failure: self.last_failure,
            _request_id: self._request_id,
        })
    }
}
