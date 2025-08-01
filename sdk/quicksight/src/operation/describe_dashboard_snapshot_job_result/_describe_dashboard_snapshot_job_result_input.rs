// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDashboardSnapshotJobResultInput {
    /// <p>The ID of the Amazon Web Services account that the dashboard snapshot job is executed in.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the dashboard that you have started a snapshot job for.</p>
    pub dashboard_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the job to be described. The job ID is set when you start a new job with a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub snapshot_job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDashboardSnapshotJobResultInput {
    /// <p>The ID of the Amazon Web Services account that the dashboard snapshot job is executed in.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the dashboard that you have started a snapshot job for.</p>
    pub fn dashboard_id(&self) -> ::std::option::Option<&str> {
        self.dashboard_id.as_deref()
    }
    /// <p>The ID of the job to be described. The job ID is set when you start a new job with a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn snapshot_job_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_job_id.as_deref()
    }
}
impl DescribeDashboardSnapshotJobResultInput {
    /// Creates a new builder-style object to manufacture [`DescribeDashboardSnapshotJobResultInput`](crate::operation::describe_dashboard_snapshot_job_result::DescribeDashboardSnapshotJobResultInput).
    pub fn builder() -> crate::operation::describe_dashboard_snapshot_job_result::builders::DescribeDashboardSnapshotJobResultInputBuilder {
        crate::operation::describe_dashboard_snapshot_job_result::builders::DescribeDashboardSnapshotJobResultInputBuilder::default()
    }
}

/// A builder for [`DescribeDashboardSnapshotJobResultInput`](crate::operation::describe_dashboard_snapshot_job_result::DescribeDashboardSnapshotJobResultInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDashboardSnapshotJobResultInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_id: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDashboardSnapshotJobResultInputBuilder {
    /// <p>The ID of the Amazon Web Services account that the dashboard snapshot job is executed in.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that the dashboard snapshot job is executed in.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that the dashboard snapshot job is executed in.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the dashboard that you have started a snapshot job for.</p>
    /// This field is required.
    pub fn dashboard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dashboard that you have started a snapshot job for.</p>
    pub fn set_dashboard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_id = input;
        self
    }
    /// <p>The ID of the dashboard that you have started a snapshot job for.</p>
    pub fn get_dashboard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_id
    }
    /// <p>The ID of the job to be described. The job ID is set when you start a new job with a <code>StartDashboardSnapshotJob</code> API call.</p>
    /// This field is required.
    pub fn snapshot_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the job to be described. The job ID is set when you start a new job with a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn set_snapshot_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_job_id = input;
        self
    }
    /// <p>The ID of the job to be described. The job ID is set when you start a new job with a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn get_snapshot_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_job_id
    }
    /// Consumes the builder and constructs a [`DescribeDashboardSnapshotJobResultInput`](crate::operation::describe_dashboard_snapshot_job_result::DescribeDashboardSnapshotJobResultInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_dashboard_snapshot_job_result::DescribeDashboardSnapshotJobResultInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_dashboard_snapshot_job_result::DescribeDashboardSnapshotJobResultInput {
                aws_account_id: self.aws_account_id,
                dashboard_id: self.dashboard_id,
                snapshot_job_id: self.snapshot_job_id,
            },
        )
    }
}
