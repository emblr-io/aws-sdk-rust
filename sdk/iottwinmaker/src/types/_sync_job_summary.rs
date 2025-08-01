// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The SyncJob summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SyncJobSummary {
    /// <p>The SyncJob summary ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the workspace that contains the sync job.</p>
    pub workspace_id: ::std::option::Option<::std::string::String>,
    /// <p>The sync source.</p>
    pub sync_source: ::std::option::Option<::std::string::String>,
    /// <p>The SyncJob summaries status.</p>
    pub status: ::std::option::Option<crate::types::SyncJobStatus>,
    /// <p>The creation date and time.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The update date and time.</p>
    pub update_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SyncJobSummary {
    /// <p>The SyncJob summary ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID of the workspace that contains the sync job.</p>
    pub fn workspace_id(&self) -> ::std::option::Option<&str> {
        self.workspace_id.as_deref()
    }
    /// <p>The sync source.</p>
    pub fn sync_source(&self) -> ::std::option::Option<&str> {
        self.sync_source.as_deref()
    }
    /// <p>The SyncJob summaries status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SyncJobStatus> {
        self.status.as_ref()
    }
    /// <p>The creation date and time.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The update date and time.</p>
    pub fn update_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.update_date_time.as_ref()
    }
}
impl SyncJobSummary {
    /// Creates a new builder-style object to manufacture [`SyncJobSummary`](crate::types::SyncJobSummary).
    pub fn builder() -> crate::types::builders::SyncJobSummaryBuilder {
        crate::types::builders::SyncJobSummaryBuilder::default()
    }
}

/// A builder for [`SyncJobSummary`](crate::types::SyncJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SyncJobSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
    pub(crate) sync_source: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SyncJobStatus>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SyncJobSummaryBuilder {
    /// <p>The SyncJob summary ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SyncJob summary ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The SyncJob summary ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the workspace that contains the sync job.</p>
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace that contains the sync job.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace that contains the sync job.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// <p>The sync source.</p>
    pub fn sync_source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sync_source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The sync source.</p>
    pub fn set_sync_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sync_source = input;
        self
    }
    /// <p>The sync source.</p>
    pub fn get_sync_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.sync_source
    }
    /// <p>The SyncJob summaries status.</p>
    pub fn status(mut self, input: crate::types::SyncJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The SyncJob summaries status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SyncJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The SyncJob summaries status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SyncJobStatus> {
        &self.status
    }
    /// <p>The creation date and time.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation date and time.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The creation date and time.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The update date and time.</p>
    pub fn update_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The update date and time.</p>
    pub fn set_update_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_date_time = input;
        self
    }
    /// <p>The update date and time.</p>
    pub fn get_update_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_date_time
    }
    /// Consumes the builder and constructs a [`SyncJobSummary`](crate::types::SyncJobSummary).
    pub fn build(self) -> crate::types::SyncJobSummary {
        crate::types::SyncJobSummary {
            arn: self.arn,
            workspace_id: self.workspace_id,
            sync_source: self.sync_source,
            status: self.status,
            creation_date_time: self.creation_date_time,
            update_date_time: self.update_date_time,
        }
    }
}
