// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detailed information about an assessment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataCollectionDetails {
    /// <p>The status of the assessment.</p>
    pub status: ::std::option::Option<crate::types::AssessmentStatus>,
    /// <p>The total number of servers in the assessment.</p>
    pub servers: ::std::option::Option<i32>,
    /// <p>The number of failed servers in the assessment.</p>
    pub failed: ::std::option::Option<i32>,
    /// <p>The number of successful servers in the assessment.</p>
    pub success: ::std::option::Option<i32>,
    /// <p>The number of servers with the assessment status <code>IN_PROGESS</code>.</p>
    pub in_progress: ::std::option::Option<i32>,
    /// <p>The start time of assessment.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time the assessment completes.</p>
    pub completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status message of the assessment.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl DataCollectionDetails {
    /// <p>The status of the assessment.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AssessmentStatus> {
        self.status.as_ref()
    }
    /// <p>The total number of servers in the assessment.</p>
    pub fn servers(&self) -> ::std::option::Option<i32> {
        self.servers
    }
    /// <p>The number of failed servers in the assessment.</p>
    pub fn failed(&self) -> ::std::option::Option<i32> {
        self.failed
    }
    /// <p>The number of successful servers in the assessment.</p>
    pub fn success(&self) -> ::std::option::Option<i32> {
        self.success
    }
    /// <p>The number of servers with the assessment status <code>IN_PROGESS</code>.</p>
    pub fn in_progress(&self) -> ::std::option::Option<i32> {
        self.in_progress
    }
    /// <p>The start time of assessment.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time the assessment completes.</p>
    pub fn completion_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_time.as_ref()
    }
    /// <p>The status message of the assessment.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl DataCollectionDetails {
    /// Creates a new builder-style object to manufacture [`DataCollectionDetails`](crate::types::DataCollectionDetails).
    pub fn builder() -> crate::types::builders::DataCollectionDetailsBuilder {
        crate::types::builders::DataCollectionDetailsBuilder::default()
    }
}

/// A builder for [`DataCollectionDetails`](crate::types::DataCollectionDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataCollectionDetailsBuilder {
    pub(crate) status: ::std::option::Option<crate::types::AssessmentStatus>,
    pub(crate) servers: ::std::option::Option<i32>,
    pub(crate) failed: ::std::option::Option<i32>,
    pub(crate) success: ::std::option::Option<i32>,
    pub(crate) in_progress: ::std::option::Option<i32>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl DataCollectionDetailsBuilder {
    /// <p>The status of the assessment.</p>
    pub fn status(mut self, input: crate::types::AssessmentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the assessment.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AssessmentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the assessment.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AssessmentStatus> {
        &self.status
    }
    /// <p>The total number of servers in the assessment.</p>
    pub fn servers(mut self, input: i32) -> Self {
        self.servers = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of servers in the assessment.</p>
    pub fn set_servers(mut self, input: ::std::option::Option<i32>) -> Self {
        self.servers = input;
        self
    }
    /// <p>The total number of servers in the assessment.</p>
    pub fn get_servers(&self) -> &::std::option::Option<i32> {
        &self.servers
    }
    /// <p>The number of failed servers in the assessment.</p>
    pub fn failed(mut self, input: i32) -> Self {
        self.failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of failed servers in the assessment.</p>
    pub fn set_failed(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed = input;
        self
    }
    /// <p>The number of failed servers in the assessment.</p>
    pub fn get_failed(&self) -> &::std::option::Option<i32> {
        &self.failed
    }
    /// <p>The number of successful servers in the assessment.</p>
    pub fn success(mut self, input: i32) -> Self {
        self.success = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of successful servers in the assessment.</p>
    pub fn set_success(mut self, input: ::std::option::Option<i32>) -> Self {
        self.success = input;
        self
    }
    /// <p>The number of successful servers in the assessment.</p>
    pub fn get_success(&self) -> &::std::option::Option<i32> {
        &self.success
    }
    /// <p>The number of servers with the assessment status <code>IN_PROGESS</code>.</p>
    pub fn in_progress(mut self, input: i32) -> Self {
        self.in_progress = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of servers with the assessment status <code>IN_PROGESS</code>.</p>
    pub fn set_in_progress(mut self, input: ::std::option::Option<i32>) -> Self {
        self.in_progress = input;
        self
    }
    /// <p>The number of servers with the assessment status <code>IN_PROGESS</code>.</p>
    pub fn get_in_progress(&self) -> &::std::option::Option<i32> {
        &self.in_progress
    }
    /// <p>The start time of assessment.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of assessment.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of assessment.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time the assessment completes.</p>
    pub fn completion_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the assessment completes.</p>
    pub fn set_completion_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_time = input;
        self
    }
    /// <p>The time the assessment completes.</p>
    pub fn get_completion_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_time
    }
    /// <p>The status message of the assessment.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message of the assessment.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The status message of the assessment.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`DataCollectionDetails`](crate::types::DataCollectionDetails).
    pub fn build(self) -> crate::types::DataCollectionDetails {
        crate::types::DataCollectionDetails {
            status: self.status,
            servers: self.servers,
            failed: self.failed,
            success: self.success,
            in_progress: self.in_progress,
            start_time: self.start_time,
            completion_time: self.completion_time,
            status_message: self.status_message,
        }
    }
}
