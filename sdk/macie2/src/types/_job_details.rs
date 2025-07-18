// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in an S3 bucket, and, if so, the details of the job that ran most recently.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobDetails {
    /// <p>Specifies whether any one-time or recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more jobs and at least one of those jobs has a status other than CANCELLED. Or the bucket matched the bucket criteria (S3BucketCriteriaForJob) for at least one job that previously ran.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any jobs, all the jobs that explicitly include the bucket in their bucket definitions have a status of CANCELLED, or the bucket didn't match the bucket criteria (S3BucketCriteriaForJob) for any jobs that previously ran.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub is_defined_in_job: ::std::option::Option<crate::types::IsDefinedInJob>,
    /// <p>Specifies whether any recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more recurring jobs or the bucket matches the bucket criteria (S3BucketCriteriaForJob) for one or more recurring jobs. At least one of those jobs has a status other than CANCELLED.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any recurring jobs, the bucket doesn't match the bucket criteria (S3BucketCriteriaForJob) for any recurring jobs, or all the recurring jobs that are configured to analyze data in the bucket have a status of CANCELLED.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub is_monitored_by_job: ::std::option::Option<crate::types::IsMonitoredByJob>,
    /// <p>The unique identifier for the job that ran most recently and is configured to analyze objects in the bucket, either the latest run of a recurring job or the only run of a one-time job.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub last_job_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the job (lastJobId) started. If the job is a recurring job, this value indicates when the most recent run started.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub last_job_run_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl JobDetails {
    /// <p>Specifies whether any one-time or recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more jobs and at least one of those jobs has a status other than CANCELLED. Or the bucket matched the bucket criteria (S3BucketCriteriaForJob) for at least one job that previously ran.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any jobs, all the jobs that explicitly include the bucket in their bucket definitions have a status of CANCELLED, or the bucket didn't match the bucket criteria (S3BucketCriteriaForJob) for any jobs that previously ran.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn is_defined_in_job(&self) -> ::std::option::Option<&crate::types::IsDefinedInJob> {
        self.is_defined_in_job.as_ref()
    }
    /// <p>Specifies whether any recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more recurring jobs or the bucket matches the bucket criteria (S3BucketCriteriaForJob) for one or more recurring jobs. At least one of those jobs has a status other than CANCELLED.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any recurring jobs, the bucket doesn't match the bucket criteria (S3BucketCriteriaForJob) for any recurring jobs, or all the recurring jobs that are configured to analyze data in the bucket have a status of CANCELLED.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn is_monitored_by_job(&self) -> ::std::option::Option<&crate::types::IsMonitoredByJob> {
        self.is_monitored_by_job.as_ref()
    }
    /// <p>The unique identifier for the job that ran most recently and is configured to analyze objects in the bucket, either the latest run of a recurring job or the only run of a one-time job.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn last_job_id(&self) -> ::std::option::Option<&str> {
        self.last_job_id.as_deref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the job (lastJobId) started. If the job is a recurring job, this value indicates when the most recent run started.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn last_job_run_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_job_run_time.as_ref()
    }
}
impl JobDetails {
    /// Creates a new builder-style object to manufacture [`JobDetails`](crate::types::JobDetails).
    pub fn builder() -> crate::types::builders::JobDetailsBuilder {
        crate::types::builders::JobDetailsBuilder::default()
    }
}

/// A builder for [`JobDetails`](crate::types::JobDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobDetailsBuilder {
    pub(crate) is_defined_in_job: ::std::option::Option<crate::types::IsDefinedInJob>,
    pub(crate) is_monitored_by_job: ::std::option::Option<crate::types::IsMonitoredByJob>,
    pub(crate) last_job_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_job_run_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl JobDetailsBuilder {
    /// <p>Specifies whether any one-time or recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more jobs and at least one of those jobs has a status other than CANCELLED. Or the bucket matched the bucket criteria (S3BucketCriteriaForJob) for at least one job that previously ran.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any jobs, all the jobs that explicitly include the bucket in their bucket definitions have a status of CANCELLED, or the bucket didn't match the bucket criteria (S3BucketCriteriaForJob) for any jobs that previously ran.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn is_defined_in_job(mut self, input: crate::types::IsDefinedInJob) -> Self {
        self.is_defined_in_job = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether any one-time or recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more jobs and at least one of those jobs has a status other than CANCELLED. Or the bucket matched the bucket criteria (S3BucketCriteriaForJob) for at least one job that previously ran.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any jobs, all the jobs that explicitly include the bucket in their bucket definitions have a status of CANCELLED, or the bucket didn't match the bucket criteria (S3BucketCriteriaForJob) for any jobs that previously ran.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn set_is_defined_in_job(mut self, input: ::std::option::Option<crate::types::IsDefinedInJob>) -> Self {
        self.is_defined_in_job = input;
        self
    }
    /// <p>Specifies whether any one-time or recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more jobs and at least one of those jobs has a status other than CANCELLED. Or the bucket matched the bucket criteria (S3BucketCriteriaForJob) for at least one job that previously ran.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any jobs, all the jobs that explicitly include the bucket in their bucket definitions have a status of CANCELLED, or the bucket didn't match the bucket criteria (S3BucketCriteriaForJob) for any jobs that previously ran.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn get_is_defined_in_job(&self) -> &::std::option::Option<crate::types::IsDefinedInJob> {
        &self.is_defined_in_job
    }
    /// <p>Specifies whether any recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more recurring jobs or the bucket matches the bucket criteria (S3BucketCriteriaForJob) for one or more recurring jobs. At least one of those jobs has a status other than CANCELLED.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any recurring jobs, the bucket doesn't match the bucket criteria (S3BucketCriteriaForJob) for any recurring jobs, or all the recurring jobs that are configured to analyze data in the bucket have a status of CANCELLED.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn is_monitored_by_job(mut self, input: crate::types::IsMonitoredByJob) -> Self {
        self.is_monitored_by_job = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether any recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more recurring jobs or the bucket matches the bucket criteria (S3BucketCriteriaForJob) for one or more recurring jobs. At least one of those jobs has a status other than CANCELLED.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any recurring jobs, the bucket doesn't match the bucket criteria (S3BucketCriteriaForJob) for any recurring jobs, or all the recurring jobs that are configured to analyze data in the bucket have a status of CANCELLED.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn set_is_monitored_by_job(mut self, input: ::std::option::Option<crate::types::IsMonitoredByJob>) -> Self {
        self.is_monitored_by_job = input;
        self
    }
    /// <p>Specifies whether any recurring jobs are configured to analyze objects in the bucket. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>TRUE - The bucket is explicitly included in the bucket definition (S3BucketDefinitionForJob) for one or more recurring jobs or the bucket matches the bucket criteria (S3BucketCriteriaForJob) for one or more recurring jobs. At least one of those jobs has a status other than CANCELLED.</p></li>
    /// <li>
    /// <p>FALSE - The bucket isn't explicitly included in the bucket definition (S3BucketDefinitionForJob) for any recurring jobs, the bucket doesn't match the bucket criteria (S3BucketCriteriaForJob) for any recurring jobs, or all the recurring jobs that are configured to analyze data in the bucket have a status of CANCELLED.</p></li>
    /// <li>
    /// <p>UNKNOWN - An exception occurred when Amazon Macie attempted to retrieve job data for the bucket.</p></li>
    /// </ul>
    pub fn get_is_monitored_by_job(&self) -> &::std::option::Option<crate::types::IsMonitoredByJob> {
        &self.is_monitored_by_job
    }
    /// <p>The unique identifier for the job that ran most recently and is configured to analyze objects in the bucket, either the latest run of a recurring job or the only run of a one-time job.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn last_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the job that ran most recently and is configured to analyze objects in the bucket, either the latest run of a recurring job or the only run of a one-time job.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn set_last_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_job_id = input;
        self
    }
    /// <p>The unique identifier for the job that ran most recently and is configured to analyze objects in the bucket, either the latest run of a recurring job or the only run of a one-time job.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn get_last_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_job_id
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the job (lastJobId) started. If the job is a recurring job, this value indicates when the most recent run started.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn last_job_run_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_job_run_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the job (lastJobId) started. If the job is a recurring job, this value indicates when the most recent run started.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn set_last_job_run_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_job_run_time = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the job (lastJobId) started. If the job is a recurring job, this value indicates when the most recent run started.</p>
    /// <p>This value is typically null if the value for the isDefinedInJob property is FALSE or UNKNOWN.</p>
    pub fn get_last_job_run_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_job_run_time
    }
    /// Consumes the builder and constructs a [`JobDetails`](crate::types::JobDetails).
    pub fn build(self) -> crate::types::JobDetails {
        crate::types::JobDetails {
            is_defined_in_job: self.is_defined_in_job,
            is_monitored_by_job: self.is_monitored_by_job,
            last_job_id: self.last_job_id,
            last_job_run_time: self.last_job_run_time,
        }
    }
}
