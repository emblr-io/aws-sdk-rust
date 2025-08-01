// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the summary of the code review.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeReviewSummary {
    /// <p>The name of the code review.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub code_review_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the repository.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The provider type of the repository association.</p>
    pub provider_type: ::std::option::Option<crate::types::ProviderType>,
    /// <p>The state of the code review.</p>
    /// <p>The valid code review states are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code>: The code review is complete.</p></li>
    /// <li>
    /// <p><code>Pending</code>: The code review started and has not completed or failed.</p></li>
    /// <li>
    /// <p><code>Failed</code>: The code review failed.</p></li>
    /// <li>
    /// <p><code>Deleting</code>: The code review is being deleted.</p></li>
    /// </ul>
    pub state: ::std::option::Option<crate::types::JobState>,
    /// <p>The time, in milliseconds since the epoch, when the code review was created.</p>
    pub created_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time, in milliseconds since the epoch, when the code review was last updated.</p>
    pub last_updated_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The type of the code review.</p>
    pub r#type: ::std::option::Option<crate::types::Type>,
    /// <p>The pull request ID for the code review.</p>
    pub pull_request_id: ::std::option::Option<::std::string::String>,
    /// <p>The statistics from the code review.</p>
    pub metrics_summary: ::std::option::Option<crate::types::MetricsSummary>,
    /// <p>Specifies the source code that is analyzed in a code review.</p>
    pub source_code_type: ::std::option::Option<crate::types::SourceCodeType>,
}
impl CodeReviewSummary {
    /// <p>The name of the code review.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn code_review_arn(&self) -> ::std::option::Option<&str> {
        self.code_review_arn.as_deref()
    }
    /// <p>The name of the repository.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The provider type of the repository association.</p>
    pub fn provider_type(&self) -> ::std::option::Option<&crate::types::ProviderType> {
        self.provider_type.as_ref()
    }
    /// <p>The state of the code review.</p>
    /// <p>The valid code review states are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code>: The code review is complete.</p></li>
    /// <li>
    /// <p><code>Pending</code>: The code review started and has not completed or failed.</p></li>
    /// <li>
    /// <p><code>Failed</code>: The code review failed.</p></li>
    /// <li>
    /// <p><code>Deleting</code>: The code review is being deleted.</p></li>
    /// </ul>
    pub fn state(&self) -> ::std::option::Option<&crate::types::JobState> {
        self.state.as_ref()
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was created.</p>
    pub fn created_time_stamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time_stamp.as_ref()
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was last updated.</p>
    pub fn last_updated_time_stamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time_stamp.as_ref()
    }
    /// <p>The type of the code review.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::Type> {
        self.r#type.as_ref()
    }
    /// <p>The pull request ID for the code review.</p>
    pub fn pull_request_id(&self) -> ::std::option::Option<&str> {
        self.pull_request_id.as_deref()
    }
    /// <p>The statistics from the code review.</p>
    pub fn metrics_summary(&self) -> ::std::option::Option<&crate::types::MetricsSummary> {
        self.metrics_summary.as_ref()
    }
    /// <p>Specifies the source code that is analyzed in a code review.</p>
    pub fn source_code_type(&self) -> ::std::option::Option<&crate::types::SourceCodeType> {
        self.source_code_type.as_ref()
    }
}
impl CodeReviewSummary {
    /// Creates a new builder-style object to manufacture [`CodeReviewSummary`](crate::types::CodeReviewSummary).
    pub fn builder() -> crate::types::builders::CodeReviewSummaryBuilder {
        crate::types::builders::CodeReviewSummaryBuilder::default()
    }
}

/// A builder for [`CodeReviewSummary`](crate::types::CodeReviewSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeReviewSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) code_review_arn: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) provider_type: ::std::option::Option<crate::types::ProviderType>,
    pub(crate) state: ::std::option::Option<crate::types::JobState>,
    pub(crate) created_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) r#type: ::std::option::Option<crate::types::Type>,
    pub(crate) pull_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) metrics_summary: ::std::option::Option<crate::types::MetricsSummary>,
    pub(crate) source_code_type: ::std::option::Option<crate::types::SourceCodeType>,
}
impl CodeReviewSummaryBuilder {
    /// <p>The name of the code review.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the code review.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the code review.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn code_review_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_review_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn set_code_review_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_review_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn get_code_review_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_review_arn
    }
    /// <p>The name of the repository.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The provider type of the repository association.</p>
    pub fn provider_type(mut self, input: crate::types::ProviderType) -> Self {
        self.provider_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The provider type of the repository association.</p>
    pub fn set_provider_type(mut self, input: ::std::option::Option<crate::types::ProviderType>) -> Self {
        self.provider_type = input;
        self
    }
    /// <p>The provider type of the repository association.</p>
    pub fn get_provider_type(&self) -> &::std::option::Option<crate::types::ProviderType> {
        &self.provider_type
    }
    /// <p>The state of the code review.</p>
    /// <p>The valid code review states are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code>: The code review is complete.</p></li>
    /// <li>
    /// <p><code>Pending</code>: The code review started and has not completed or failed.</p></li>
    /// <li>
    /// <p><code>Failed</code>: The code review failed.</p></li>
    /// <li>
    /// <p><code>Deleting</code>: The code review is being deleted.</p></li>
    /// </ul>
    pub fn state(mut self, input: crate::types::JobState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the code review.</p>
    /// <p>The valid code review states are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code>: The code review is complete.</p></li>
    /// <li>
    /// <p><code>Pending</code>: The code review started and has not completed or failed.</p></li>
    /// <li>
    /// <p><code>Failed</code>: The code review failed.</p></li>
    /// <li>
    /// <p><code>Deleting</code>: The code review is being deleted.</p></li>
    /// </ul>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::JobState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the code review.</p>
    /// <p>The valid code review states are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code>: The code review is complete.</p></li>
    /// <li>
    /// <p><code>Pending</code>: The code review started and has not completed or failed.</p></li>
    /// <li>
    /// <p><code>Failed</code>: The code review failed.</p></li>
    /// <li>
    /// <p><code>Deleting</code>: The code review is being deleted.</p></li>
    /// </ul>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::JobState> {
        &self.state
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was created.</p>
    pub fn created_time_stamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time_stamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was created.</p>
    pub fn set_created_time_stamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time_stamp = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was created.</p>
    pub fn get_created_time_stamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time_stamp
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was last updated.</p>
    pub fn last_updated_time_stamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time_stamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was last updated.</p>
    pub fn set_last_updated_time_stamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time_stamp = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the code review was last updated.</p>
    pub fn get_last_updated_time_stamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time_stamp
    }
    /// <p>The type of the code review.</p>
    pub fn r#type(mut self, input: crate::types::Type) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the code review.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Type>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the code review.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Type> {
        &self.r#type
    }
    /// <p>The pull request ID for the code review.</p>
    pub fn pull_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pull_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pull request ID for the code review.</p>
    pub fn set_pull_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pull_request_id = input;
        self
    }
    /// <p>The pull request ID for the code review.</p>
    pub fn get_pull_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pull_request_id
    }
    /// <p>The statistics from the code review.</p>
    pub fn metrics_summary(mut self, input: crate::types::MetricsSummary) -> Self {
        self.metrics_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The statistics from the code review.</p>
    pub fn set_metrics_summary(mut self, input: ::std::option::Option<crate::types::MetricsSummary>) -> Self {
        self.metrics_summary = input;
        self
    }
    /// <p>The statistics from the code review.</p>
    pub fn get_metrics_summary(&self) -> &::std::option::Option<crate::types::MetricsSummary> {
        &self.metrics_summary
    }
    /// <p>Specifies the source code that is analyzed in a code review.</p>
    pub fn source_code_type(mut self, input: crate::types::SourceCodeType) -> Self {
        self.source_code_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the source code that is analyzed in a code review.</p>
    pub fn set_source_code_type(mut self, input: ::std::option::Option<crate::types::SourceCodeType>) -> Self {
        self.source_code_type = input;
        self
    }
    /// <p>Specifies the source code that is analyzed in a code review.</p>
    pub fn get_source_code_type(&self) -> &::std::option::Option<crate::types::SourceCodeType> {
        &self.source_code_type
    }
    /// Consumes the builder and constructs a [`CodeReviewSummary`](crate::types::CodeReviewSummary).
    pub fn build(self) -> crate::types::CodeReviewSummary {
        crate::types::CodeReviewSummary {
            name: self.name,
            code_review_arn: self.code_review_arn,
            repository_name: self.repository_name,
            owner: self.owner,
            provider_type: self.provider_type,
            state: self.state,
            created_time_stamp: self.created_time_stamp,
            last_updated_time_stamp: self.last_updated_time_stamp,
            r#type: self.r#type,
            pull_request_id: self.pull_request_id,
            metrics_summary: self.metrics_summary,
            source_code_type: self.source_code_type,
        }
    }
}
