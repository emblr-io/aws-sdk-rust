// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains all the information about a speaker enrollment job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SpeakerEnrollmentJob {
    /// <p>The client-provided name for the speaker enrollment job.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The service-generated identifier for the speaker enrollment job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the speaker enrollment job.</p>
    pub job_status: ::std::option::Option<crate::types::SpeakerEnrollmentJobStatus>,
    /// <p>The identifier of the domain that contains the speaker enrollment job.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The IAM role Amazon Resource Name (ARN) that grants Voice ID permissions to access customer's buckets to read the input manifest file and write the job output file.</p>
    pub data_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The configuration that defines the action to take when the speaker is already enrolled in Voice ID, and the <code>FraudDetectionConfig</code> to use.</p>
    pub enrollment_config: ::std::option::Option<crate::types::EnrollmentConfig>,
    /// <p>The input data config containing an S3 URI for the input manifest file that contains the list of speaker enrollment job requests.</p>
    pub input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    /// <p>The output data config containing the S3 location where Voice ID writes the job output file; you must also include a KMS key ID to encrypt the file.</p>
    pub output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    /// <p>A timestamp of when the speaker enrollment job was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp of when the speaker enrollment job ended.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Contains details that are populated when an entire batch job fails. In cases of individual registration job failures, the batch job as a whole doesn't fail; it is completed with a <code>JobStatus</code> of <code>COMPLETED_WITH_ERRORS</code>. You can use the job output file to identify the individual registration requests that failed.</p>
    pub failure_details: ::std::option::Option<crate::types::FailureDetails>,
    /// <p>Provides details on job progress. This field shows the completed percentage of registration requests listed in the input file.</p>
    pub job_progress: ::std::option::Option<crate::types::JobProgress>,
}
impl SpeakerEnrollmentJob {
    /// <p>The client-provided name for the speaker enrollment job.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The service-generated identifier for the speaker enrollment job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The current status of the speaker enrollment job.</p>
    pub fn job_status(&self) -> ::std::option::Option<&crate::types::SpeakerEnrollmentJobStatus> {
        self.job_status.as_ref()
    }
    /// <p>The identifier of the domain that contains the speaker enrollment job.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The IAM role Amazon Resource Name (ARN) that grants Voice ID permissions to access customer's buckets to read the input manifest file and write the job output file.</p>
    pub fn data_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.data_access_role_arn.as_deref()
    }
    /// <p>The configuration that defines the action to take when the speaker is already enrolled in Voice ID, and the <code>FraudDetectionConfig</code> to use.</p>
    pub fn enrollment_config(&self) -> ::std::option::Option<&crate::types::EnrollmentConfig> {
        self.enrollment_config.as_ref()
    }
    /// <p>The input data config containing an S3 URI for the input manifest file that contains the list of speaker enrollment job requests.</p>
    pub fn input_data_config(&self) -> ::std::option::Option<&crate::types::InputDataConfig> {
        self.input_data_config.as_ref()
    }
    /// <p>The output data config containing the S3 location where Voice ID writes the job output file; you must also include a KMS key ID to encrypt the file.</p>
    pub fn output_data_config(&self) -> ::std::option::Option<&crate::types::OutputDataConfig> {
        self.output_data_config.as_ref()
    }
    /// <p>A timestamp of when the speaker enrollment job was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>A timestamp of when the speaker enrollment job ended.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>Contains details that are populated when an entire batch job fails. In cases of individual registration job failures, the batch job as a whole doesn't fail; it is completed with a <code>JobStatus</code> of <code>COMPLETED_WITH_ERRORS</code>. You can use the job output file to identify the individual registration requests that failed.</p>
    pub fn failure_details(&self) -> ::std::option::Option<&crate::types::FailureDetails> {
        self.failure_details.as_ref()
    }
    /// <p>Provides details on job progress. This field shows the completed percentage of registration requests listed in the input file.</p>
    pub fn job_progress(&self) -> ::std::option::Option<&crate::types::JobProgress> {
        self.job_progress.as_ref()
    }
}
impl ::std::fmt::Debug for SpeakerEnrollmentJob {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SpeakerEnrollmentJob");
        formatter.field("job_name", &"*** Sensitive Data Redacted ***");
        formatter.field("job_id", &self.job_id);
        formatter.field("job_status", &self.job_status);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("data_access_role_arn", &self.data_access_role_arn);
        formatter.field("enrollment_config", &self.enrollment_config);
        formatter.field("input_data_config", &self.input_data_config);
        formatter.field("output_data_config", &self.output_data_config);
        formatter.field("created_at", &self.created_at);
        formatter.field("ended_at", &self.ended_at);
        formatter.field("failure_details", &self.failure_details);
        formatter.field("job_progress", &self.job_progress);
        formatter.finish()
    }
}
impl SpeakerEnrollmentJob {
    /// Creates a new builder-style object to manufacture [`SpeakerEnrollmentJob`](crate::types::SpeakerEnrollmentJob).
    pub fn builder() -> crate::types::builders::SpeakerEnrollmentJobBuilder {
        crate::types::builders::SpeakerEnrollmentJobBuilder::default()
    }
}

/// A builder for [`SpeakerEnrollmentJob`](crate::types::SpeakerEnrollmentJob).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SpeakerEnrollmentJobBuilder {
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::SpeakerEnrollmentJobStatus>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) enrollment_config: ::std::option::Option<crate::types::EnrollmentConfig>,
    pub(crate) input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    pub(crate) output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) failure_details: ::std::option::Option<crate::types::FailureDetails>,
    pub(crate) job_progress: ::std::option::Option<crate::types::JobProgress>,
}
impl SpeakerEnrollmentJobBuilder {
    /// <p>The client-provided name for the speaker enrollment job.</p>
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client-provided name for the speaker enrollment job.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The client-provided name for the speaker enrollment job.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The service-generated identifier for the speaker enrollment job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service-generated identifier for the speaker enrollment job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The service-generated identifier for the speaker enrollment job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The current status of the speaker enrollment job.</p>
    pub fn job_status(mut self, input: crate::types::SpeakerEnrollmentJobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the speaker enrollment job.</p>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::SpeakerEnrollmentJobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The current status of the speaker enrollment job.</p>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::SpeakerEnrollmentJobStatus> {
        &self.job_status
    }
    /// <p>The identifier of the domain that contains the speaker enrollment job.</p>
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the domain that contains the speaker enrollment job.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the domain that contains the speaker enrollment job.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The IAM role Amazon Resource Name (ARN) that grants Voice ID permissions to access customer's buckets to read the input manifest file and write the job output file.</p>
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role Amazon Resource Name (ARN) that grants Voice ID permissions to access customer's buckets to read the input manifest file and write the job output file.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The IAM role Amazon Resource Name (ARN) that grants Voice ID permissions to access customer's buckets to read the input manifest file and write the job output file.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// <p>The configuration that defines the action to take when the speaker is already enrolled in Voice ID, and the <code>FraudDetectionConfig</code> to use.</p>
    pub fn enrollment_config(mut self, input: crate::types::EnrollmentConfig) -> Self {
        self.enrollment_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that defines the action to take when the speaker is already enrolled in Voice ID, and the <code>FraudDetectionConfig</code> to use.</p>
    pub fn set_enrollment_config(mut self, input: ::std::option::Option<crate::types::EnrollmentConfig>) -> Self {
        self.enrollment_config = input;
        self
    }
    /// <p>The configuration that defines the action to take when the speaker is already enrolled in Voice ID, and the <code>FraudDetectionConfig</code> to use.</p>
    pub fn get_enrollment_config(&self) -> &::std::option::Option<crate::types::EnrollmentConfig> {
        &self.enrollment_config
    }
    /// <p>The input data config containing an S3 URI for the input manifest file that contains the list of speaker enrollment job requests.</p>
    pub fn input_data_config(mut self, input: crate::types::InputDataConfig) -> Self {
        self.input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input data config containing an S3 URI for the input manifest file that contains the list of speaker enrollment job requests.</p>
    pub fn set_input_data_config(mut self, input: ::std::option::Option<crate::types::InputDataConfig>) -> Self {
        self.input_data_config = input;
        self
    }
    /// <p>The input data config containing an S3 URI for the input manifest file that contains the list of speaker enrollment job requests.</p>
    pub fn get_input_data_config(&self) -> &::std::option::Option<crate::types::InputDataConfig> {
        &self.input_data_config
    }
    /// <p>The output data config containing the S3 location where Voice ID writes the job output file; you must also include a KMS key ID to encrypt the file.</p>
    pub fn output_data_config(mut self, input: crate::types::OutputDataConfig) -> Self {
        self.output_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output data config containing the S3 location where Voice ID writes the job output file; you must also include a KMS key ID to encrypt the file.</p>
    pub fn set_output_data_config(mut self, input: ::std::option::Option<crate::types::OutputDataConfig>) -> Self {
        self.output_data_config = input;
        self
    }
    /// <p>The output data config containing the S3 location where Voice ID writes the job output file; you must also include a KMS key ID to encrypt the file.</p>
    pub fn get_output_data_config(&self) -> &::std::option::Option<crate::types::OutputDataConfig> {
        &self.output_data_config
    }
    /// <p>A timestamp of when the speaker enrollment job was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp of when the speaker enrollment job was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>A timestamp of when the speaker enrollment job was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>A timestamp of when the speaker enrollment job ended.</p>
    pub fn ended_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.ended_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp of when the speaker enrollment job ended.</p>
    pub fn set_ended_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.ended_at = input;
        self
    }
    /// <p>A timestamp of when the speaker enrollment job ended.</p>
    pub fn get_ended_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.ended_at
    }
    /// <p>Contains details that are populated when an entire batch job fails. In cases of individual registration job failures, the batch job as a whole doesn't fail; it is completed with a <code>JobStatus</code> of <code>COMPLETED_WITH_ERRORS</code>. You can use the job output file to identify the individual registration requests that failed.</p>
    pub fn failure_details(mut self, input: crate::types::FailureDetails) -> Self {
        self.failure_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details that are populated when an entire batch job fails. In cases of individual registration job failures, the batch job as a whole doesn't fail; it is completed with a <code>JobStatus</code> of <code>COMPLETED_WITH_ERRORS</code>. You can use the job output file to identify the individual registration requests that failed.</p>
    pub fn set_failure_details(mut self, input: ::std::option::Option<crate::types::FailureDetails>) -> Self {
        self.failure_details = input;
        self
    }
    /// <p>Contains details that are populated when an entire batch job fails. In cases of individual registration job failures, the batch job as a whole doesn't fail; it is completed with a <code>JobStatus</code> of <code>COMPLETED_WITH_ERRORS</code>. You can use the job output file to identify the individual registration requests that failed.</p>
    pub fn get_failure_details(&self) -> &::std::option::Option<crate::types::FailureDetails> {
        &self.failure_details
    }
    /// <p>Provides details on job progress. This field shows the completed percentage of registration requests listed in the input file.</p>
    pub fn job_progress(mut self, input: crate::types::JobProgress) -> Self {
        self.job_progress = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details on job progress. This field shows the completed percentage of registration requests listed in the input file.</p>
    pub fn set_job_progress(mut self, input: ::std::option::Option<crate::types::JobProgress>) -> Self {
        self.job_progress = input;
        self
    }
    /// <p>Provides details on job progress. This field shows the completed percentage of registration requests listed in the input file.</p>
    pub fn get_job_progress(&self) -> &::std::option::Option<crate::types::JobProgress> {
        &self.job_progress
    }
    /// Consumes the builder and constructs a [`SpeakerEnrollmentJob`](crate::types::SpeakerEnrollmentJob).
    pub fn build(self) -> crate::types::SpeakerEnrollmentJob {
        crate::types::SpeakerEnrollmentJob {
            job_name: self.job_name,
            job_id: self.job_id,
            job_status: self.job_status,
            domain_id: self.domain_id,
            data_access_role_arn: self.data_access_role_arn,
            enrollment_config: self.enrollment_config,
            input_data_config: self.input_data_config,
            output_data_config: self.output_data_config,
            created_at: self.created_at,
            ended_at: self.ended_at,
            failure_details: self.failure_details,
            job_progress: self.job_progress,
        }
    }
}
impl ::std::fmt::Debug for SpeakerEnrollmentJobBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SpeakerEnrollmentJobBuilder");
        formatter.field("job_name", &"*** Sensitive Data Redacted ***");
        formatter.field("job_id", &self.job_id);
        formatter.field("job_status", &self.job_status);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("data_access_role_arn", &self.data_access_role_arn);
        formatter.field("enrollment_config", &self.enrollment_config);
        formatter.field("input_data_config", &self.input_data_config);
        formatter.field("output_data_config", &self.output_data_config);
        formatter.field("created_at", &self.created_at);
        formatter.field("ended_at", &self.ended_at);
        formatter.field("failure_details", &self.failure_details);
        formatter.field("job_progress", &self.job_progress);
        formatter.finish()
    }
}
