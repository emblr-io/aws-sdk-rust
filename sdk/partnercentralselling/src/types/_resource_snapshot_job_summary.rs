// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains a <code>Resource Snapshot Job</code>'s subset of fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceSnapshotJobSummary {
    /// <p>The unique identifier for the resource snapshot job within the AWS Partner Central system. This ID is used for direct references to the job within the service.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the resource snapshot job.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the Engagement.</p>
    pub engagement_id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the snapshot job.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
}
impl ResourceSnapshotJobSummary {
    /// <p>The unique identifier for the resource snapshot job within the AWS Partner Central system. This ID is used for direct references to the job within the service.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the resource snapshot job.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The unique identifier of the Engagement.</p>
    pub fn engagement_id(&self) -> ::std::option::Option<&str> {
        self.engagement_id.as_deref()
    }
    /// <p>The current status of the snapshot job.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceSnapshotJobStatus> {
        self.status.as_ref()
    }
}
impl ResourceSnapshotJobSummary {
    /// Creates a new builder-style object to manufacture [`ResourceSnapshotJobSummary`](crate::types::ResourceSnapshotJobSummary).
    pub fn builder() -> crate::types::builders::ResourceSnapshotJobSummaryBuilder {
        crate::types::builders::ResourceSnapshotJobSummaryBuilder::default()
    }
}

/// A builder for [`ResourceSnapshotJobSummary`](crate::types::ResourceSnapshotJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceSnapshotJobSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) engagement_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
}
impl ResourceSnapshotJobSummaryBuilder {
    /// <p>The unique identifier for the resource snapshot job within the AWS Partner Central system. This ID is used for direct references to the job within the service.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the resource snapshot job within the AWS Partner Central system. This ID is used for direct references to the job within the service.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the resource snapshot job within the AWS Partner Central system. This ID is used for direct references to the job within the service.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) for the resource snapshot job.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the resource snapshot job.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the resource snapshot job.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The unique identifier of the Engagement.</p>
    pub fn engagement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engagement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Engagement.</p>
    pub fn set_engagement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engagement_id = input;
        self
    }
    /// <p>The unique identifier of the Engagement.</p>
    pub fn get_engagement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.engagement_id
    }
    /// <p>The current status of the snapshot job.</p>
    /// <p>Valid values:</p>
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
    /// <p>The current status of the snapshot job.</p>
    /// <p>Valid values:</p>
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
    /// <p>The current status of the snapshot job.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>STOPPED: The job is not currently running.</p></li>
    /// <li>
    /// <p>RUNNING: The job is actively executing.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceSnapshotJobStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ResourceSnapshotJobSummary`](crate::types::ResourceSnapshotJobSummary).
    pub fn build(self) -> crate::types::ResourceSnapshotJobSummary {
        crate::types::ResourceSnapshotJobSummary {
            id: self.id,
            arn: self.arn,
            engagement_id: self.engagement_id,
            status: self.status,
        }
    }
}
