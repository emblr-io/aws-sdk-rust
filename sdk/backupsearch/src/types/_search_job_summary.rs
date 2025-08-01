// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This is information pertaining to a search job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchJobSummary {
    /// <p>The unique string that specifies the search job.</p>
    pub search_job_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The unique string that identifies the Amazon Resource Name (ARN) of the specified search job.</p>
    pub search_job_arn: ::std::option::Option<::std::string::String>,
    /// <p>This is the name of the search job.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>This is the status of the search job.</p>
    pub status: ::std::option::Option<crate::types::SearchJobState>,
    /// <p>This is the creation time of the search job.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>This is the completion time of the search job.</p>
    pub completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Returned summary of the specified search job scope, including:</p>
    /// <ul>
    /// <li>
    /// <p>TotalBackupsToScanCount, the number of recovery points returned by the search.</p></li>
    /// <li>
    /// <p>TotalItemsToScanCount, the number of items returned by the search.</p></li>
    /// </ul>
    pub search_scope_summary: ::std::option::Option<crate::types::SearchScopeSummary>,
    /// <p>A status message will be returned for either a earch job with a status of <code>ERRORED</code> or a status of <code>COMPLETED</code> jobs with issues.</p>
    /// <p>For example, a message may say that a search contained recovery points unable to be scanned because of a permissions issue.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl SearchJobSummary {
    /// <p>The unique string that specifies the search job.</p>
    pub fn search_job_identifier(&self) -> ::std::option::Option<&str> {
        self.search_job_identifier.as_deref()
    }
    /// <p>The unique string that identifies the Amazon Resource Name (ARN) of the specified search job.</p>
    pub fn search_job_arn(&self) -> ::std::option::Option<&str> {
        self.search_job_arn.as_deref()
    }
    /// <p>This is the name of the search job.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>This is the status of the search job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SearchJobState> {
        self.status.as_ref()
    }
    /// <p>This is the creation time of the search job.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>This is the completion time of the search job.</p>
    pub fn completion_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_time.as_ref()
    }
    /// <p>Returned summary of the specified search job scope, including:</p>
    /// <ul>
    /// <li>
    /// <p>TotalBackupsToScanCount, the number of recovery points returned by the search.</p></li>
    /// <li>
    /// <p>TotalItemsToScanCount, the number of items returned by the search.</p></li>
    /// </ul>
    pub fn search_scope_summary(&self) -> ::std::option::Option<&crate::types::SearchScopeSummary> {
        self.search_scope_summary.as_ref()
    }
    /// <p>A status message will be returned for either a earch job with a status of <code>ERRORED</code> or a status of <code>COMPLETED</code> jobs with issues.</p>
    /// <p>For example, a message may say that a search contained recovery points unable to be scanned because of a permissions issue.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl SearchJobSummary {
    /// Creates a new builder-style object to manufacture [`SearchJobSummary`](crate::types::SearchJobSummary).
    pub fn builder() -> crate::types::builders::SearchJobSummaryBuilder {
        crate::types::builders::SearchJobSummaryBuilder::default()
    }
}

/// A builder for [`SearchJobSummary`](crate::types::SearchJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchJobSummaryBuilder {
    pub(crate) search_job_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) search_job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SearchJobState>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) search_scope_summary: ::std::option::Option<crate::types::SearchScopeSummary>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl SearchJobSummaryBuilder {
    /// <p>The unique string that specifies the search job.</p>
    pub fn search_job_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.search_job_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique string that specifies the search job.</p>
    pub fn set_search_job_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.search_job_identifier = input;
        self
    }
    /// <p>The unique string that specifies the search job.</p>
    pub fn get_search_job_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.search_job_identifier
    }
    /// <p>The unique string that identifies the Amazon Resource Name (ARN) of the specified search job.</p>
    pub fn search_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.search_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique string that identifies the Amazon Resource Name (ARN) of the specified search job.</p>
    pub fn set_search_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.search_job_arn = input;
        self
    }
    /// <p>The unique string that identifies the Amazon Resource Name (ARN) of the specified search job.</p>
    pub fn get_search_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.search_job_arn
    }
    /// <p>This is the name of the search job.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is the name of the search job.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>This is the name of the search job.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>This is the status of the search job.</p>
    pub fn status(mut self, input: crate::types::SearchJobState) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the status of the search job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SearchJobState>) -> Self {
        self.status = input;
        self
    }
    /// <p>This is the status of the search job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SearchJobState> {
        &self.status
    }
    /// <p>This is the creation time of the search job.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the creation time of the search job.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>This is the creation time of the search job.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>This is the completion time of the search job.</p>
    pub fn completion_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the completion time of the search job.</p>
    pub fn set_completion_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_time = input;
        self
    }
    /// <p>This is the completion time of the search job.</p>
    pub fn get_completion_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_time
    }
    /// <p>Returned summary of the specified search job scope, including:</p>
    /// <ul>
    /// <li>
    /// <p>TotalBackupsToScanCount, the number of recovery points returned by the search.</p></li>
    /// <li>
    /// <p>TotalItemsToScanCount, the number of items returned by the search.</p></li>
    /// </ul>
    pub fn search_scope_summary(mut self, input: crate::types::SearchScopeSummary) -> Self {
        self.search_scope_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returned summary of the specified search job scope, including:</p>
    /// <ul>
    /// <li>
    /// <p>TotalBackupsToScanCount, the number of recovery points returned by the search.</p></li>
    /// <li>
    /// <p>TotalItemsToScanCount, the number of items returned by the search.</p></li>
    /// </ul>
    pub fn set_search_scope_summary(mut self, input: ::std::option::Option<crate::types::SearchScopeSummary>) -> Self {
        self.search_scope_summary = input;
        self
    }
    /// <p>Returned summary of the specified search job scope, including:</p>
    /// <ul>
    /// <li>
    /// <p>TotalBackupsToScanCount, the number of recovery points returned by the search.</p></li>
    /// <li>
    /// <p>TotalItemsToScanCount, the number of items returned by the search.</p></li>
    /// </ul>
    pub fn get_search_scope_summary(&self) -> &::std::option::Option<crate::types::SearchScopeSummary> {
        &self.search_scope_summary
    }
    /// <p>A status message will be returned for either a earch job with a status of <code>ERRORED</code> or a status of <code>COMPLETED</code> jobs with issues.</p>
    /// <p>For example, a message may say that a search contained recovery points unable to be scanned because of a permissions issue.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A status message will be returned for either a earch job with a status of <code>ERRORED</code> or a status of <code>COMPLETED</code> jobs with issues.</p>
    /// <p>For example, a message may say that a search contained recovery points unable to be scanned because of a permissions issue.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A status message will be returned for either a earch job with a status of <code>ERRORED</code> or a status of <code>COMPLETED</code> jobs with issues.</p>
    /// <p>For example, a message may say that a search contained recovery points unable to be scanned because of a permissions issue.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`SearchJobSummary`](crate::types::SearchJobSummary).
    pub fn build(self) -> crate::types::SearchJobSummary {
        crate::types::SearchJobSummary {
            search_job_identifier: self.search_job_identifier,
            search_job_arn: self.search_job_arn,
            name: self.name,
            status: self.status,
            creation_time: self.creation_time,
            completion_time: self.completion_time,
            search_scope_summary: self.search_scope_summary,
            status_message: self.status_message,
        }
    }
}
