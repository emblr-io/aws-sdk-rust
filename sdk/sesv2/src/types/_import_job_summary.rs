// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the import job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportJobSummary {
    /// <p>A string that represents a job ID.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>An object that contains details about the resource destination the import job is going to target.</p>
    pub import_destination: ::std::option::Option<crate::types::ImportDestination>,
    /// <p>The status of a job.</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATED</code> – Job has just been created.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code> – Job is processing.</p></li>
    /// <li>
    /// <p><code>ERROR</code> – An error occurred during processing.</p></li>
    /// <li>
    /// <p><code>COMPLETED</code> – Job has completed processing successfully.</p></li>
    /// </ul>
    pub job_status: ::std::option::Option<crate::types::JobStatus>,
    /// <p>The date and time when the import job was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current number of records processed.</p>
    pub processed_records_count: ::std::option::Option<i32>,
    /// <p>The number of records that failed processing because of invalid input or other reasons.</p>
    pub failed_records_count: ::std::option::Option<i32>,
}
impl ImportJobSummary {
    /// <p>A string that represents a job ID.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>An object that contains details about the resource destination the import job is going to target.</p>
    pub fn import_destination(&self) -> ::std::option::Option<&crate::types::ImportDestination> {
        self.import_destination.as_ref()
    }
    /// <p>The status of a job.</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATED</code> – Job has just been created.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code> – Job is processing.</p></li>
    /// <li>
    /// <p><code>ERROR</code> – An error occurred during processing.</p></li>
    /// <li>
    /// <p><code>COMPLETED</code> – Job has completed processing successfully.</p></li>
    /// </ul>
    pub fn job_status(&self) -> ::std::option::Option<&crate::types::JobStatus> {
        self.job_status.as_ref()
    }
    /// <p>The date and time when the import job was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The current number of records processed.</p>
    pub fn processed_records_count(&self) -> ::std::option::Option<i32> {
        self.processed_records_count
    }
    /// <p>The number of records that failed processing because of invalid input or other reasons.</p>
    pub fn failed_records_count(&self) -> ::std::option::Option<i32> {
        self.failed_records_count
    }
}
impl ImportJobSummary {
    /// Creates a new builder-style object to manufacture [`ImportJobSummary`](crate::types::ImportJobSummary).
    pub fn builder() -> crate::types::builders::ImportJobSummaryBuilder {
        crate::types::builders::ImportJobSummaryBuilder::default()
    }
}

/// A builder for [`ImportJobSummary`](crate::types::ImportJobSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportJobSummaryBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) import_destination: ::std::option::Option<crate::types::ImportDestination>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) processed_records_count: ::std::option::Option<i32>,
    pub(crate) failed_records_count: ::std::option::Option<i32>,
}
impl ImportJobSummaryBuilder {
    /// <p>A string that represents a job ID.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that represents a job ID.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>A string that represents a job ID.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>An object that contains details about the resource destination the import job is going to target.</p>
    pub fn import_destination(mut self, input: crate::types::ImportDestination) -> Self {
        self.import_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains details about the resource destination the import job is going to target.</p>
    pub fn set_import_destination(mut self, input: ::std::option::Option<crate::types::ImportDestination>) -> Self {
        self.import_destination = input;
        self
    }
    /// <p>An object that contains details about the resource destination the import job is going to target.</p>
    pub fn get_import_destination(&self) -> &::std::option::Option<crate::types::ImportDestination> {
        &self.import_destination
    }
    /// <p>The status of a job.</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATED</code> – Job has just been created.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code> – Job is processing.</p></li>
    /// <li>
    /// <p><code>ERROR</code> – An error occurred during processing.</p></li>
    /// <li>
    /// <p><code>COMPLETED</code> – Job has completed processing successfully.</p></li>
    /// </ul>
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a job.</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATED</code> – Job has just been created.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code> – Job is processing.</p></li>
    /// <li>
    /// <p><code>ERROR</code> – An error occurred during processing.</p></li>
    /// <li>
    /// <p><code>COMPLETED</code> – Job has completed processing successfully.</p></li>
    /// </ul>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The status of a job.</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATED</code> – Job has just been created.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code> – Job is processing.</p></li>
    /// <li>
    /// <p><code>ERROR</code> – An error occurred during processing.</p></li>
    /// <li>
    /// <p><code>COMPLETED</code> – Job has completed processing successfully.</p></li>
    /// </ul>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    /// <p>The date and time when the import job was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the import job was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The date and time when the import job was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The current number of records processed.</p>
    pub fn processed_records_count(mut self, input: i32) -> Self {
        self.processed_records_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current number of records processed.</p>
    pub fn set_processed_records_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.processed_records_count = input;
        self
    }
    /// <p>The current number of records processed.</p>
    pub fn get_processed_records_count(&self) -> &::std::option::Option<i32> {
        &self.processed_records_count
    }
    /// <p>The number of records that failed processing because of invalid input or other reasons.</p>
    pub fn failed_records_count(mut self, input: i32) -> Self {
        self.failed_records_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of records that failed processing because of invalid input or other reasons.</p>
    pub fn set_failed_records_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed_records_count = input;
        self
    }
    /// <p>The number of records that failed processing because of invalid input or other reasons.</p>
    pub fn get_failed_records_count(&self) -> &::std::option::Option<i32> {
        &self.failed_records_count
    }
    /// Consumes the builder and constructs a [`ImportJobSummary`](crate::types::ImportJobSummary).
    pub fn build(self) -> crate::types::ImportJobSummary {
        crate::types::ImportJobSummary {
            job_id: self.job_id,
            import_destination: self.import_destination,
            job_status: self.job_status,
            created_timestamp: self.created_timestamp,
            processed_records_count: self.processed_records_count,
            failed_records_count: self.failed_records_count,
        }
    }
}
