// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateClassificationJobInput {
    /// <p>The unique identifier for the classification job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The new status for the job. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>CANCELLED - Stops the job permanently and cancels it. This value is valid only if the job's current status is IDLE, PAUSED, RUNNING, or USER_PAUSED.</p>
    /// <p>If you specify this value and the job's current status is RUNNING, Amazon Macie immediately begins to stop all processing tasks for the job. You can't resume or restart a job after you cancel it.</p></li>
    /// <li>
    /// <p>RUNNING - Resumes the job. This value is valid only if the job's current status is USER_PAUSED.</p>
    /// <p>If you paused the job while it was actively running and you specify this value less than 30 days after you paused the job, Macie immediately resumes processing from the point where you paused the job. Otherwise, Macie resumes the job according to the schedule and other settings for the job.</p></li>
    /// <li>
    /// <p>USER_PAUSED - Pauses the job temporarily. This value is valid only if the job's current status is IDLE, PAUSED, or RUNNING. If you specify this value and the job's current status is RUNNING, Macie immediately begins to pause all processing tasks for the job.</p>
    /// <p>If you pause a one-time job and you don't resume it within 30 days, the job expires and Macie cancels the job. If you pause a recurring job when its status is RUNNING and you don't resume it within 30 days, the job run expires and Macie cancels the run. To check the expiration date, refer to the UserPausedDetails.jobExpiresAt property.</p></li>
    /// </ul>
    pub job_status: ::std::option::Option<crate::types::JobStatus>,
}
impl UpdateClassificationJobInput {
    /// <p>The unique identifier for the classification job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The new status for the job. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>CANCELLED - Stops the job permanently and cancels it. This value is valid only if the job's current status is IDLE, PAUSED, RUNNING, or USER_PAUSED.</p>
    /// <p>If you specify this value and the job's current status is RUNNING, Amazon Macie immediately begins to stop all processing tasks for the job. You can't resume or restart a job after you cancel it.</p></li>
    /// <li>
    /// <p>RUNNING - Resumes the job. This value is valid only if the job's current status is USER_PAUSED.</p>
    /// <p>If you paused the job while it was actively running and you specify this value less than 30 days after you paused the job, Macie immediately resumes processing from the point where you paused the job. Otherwise, Macie resumes the job according to the schedule and other settings for the job.</p></li>
    /// <li>
    /// <p>USER_PAUSED - Pauses the job temporarily. This value is valid only if the job's current status is IDLE, PAUSED, or RUNNING. If you specify this value and the job's current status is RUNNING, Macie immediately begins to pause all processing tasks for the job.</p>
    /// <p>If you pause a one-time job and you don't resume it within 30 days, the job expires and Macie cancels the job. If you pause a recurring job when its status is RUNNING and you don't resume it within 30 days, the job run expires and Macie cancels the run. To check the expiration date, refer to the UserPausedDetails.jobExpiresAt property.</p></li>
    /// </ul>
    pub fn job_status(&self) -> ::std::option::Option<&crate::types::JobStatus> {
        self.job_status.as_ref()
    }
}
impl UpdateClassificationJobInput {
    /// Creates a new builder-style object to manufacture [`UpdateClassificationJobInput`](crate::operation::update_classification_job::UpdateClassificationJobInput).
    pub fn builder() -> crate::operation::update_classification_job::builders::UpdateClassificationJobInputBuilder {
        crate::operation::update_classification_job::builders::UpdateClassificationJobInputBuilder::default()
    }
}

/// A builder for [`UpdateClassificationJobInput`](crate::operation::update_classification_job::UpdateClassificationJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateClassificationJobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
}
impl UpdateClassificationJobInputBuilder {
    /// <p>The unique identifier for the classification job.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the classification job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The unique identifier for the classification job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The new status for the job. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>CANCELLED - Stops the job permanently and cancels it. This value is valid only if the job's current status is IDLE, PAUSED, RUNNING, or USER_PAUSED.</p>
    /// <p>If you specify this value and the job's current status is RUNNING, Amazon Macie immediately begins to stop all processing tasks for the job. You can't resume or restart a job after you cancel it.</p></li>
    /// <li>
    /// <p>RUNNING - Resumes the job. This value is valid only if the job's current status is USER_PAUSED.</p>
    /// <p>If you paused the job while it was actively running and you specify this value less than 30 days after you paused the job, Macie immediately resumes processing from the point where you paused the job. Otherwise, Macie resumes the job according to the schedule and other settings for the job.</p></li>
    /// <li>
    /// <p>USER_PAUSED - Pauses the job temporarily. This value is valid only if the job's current status is IDLE, PAUSED, or RUNNING. If you specify this value and the job's current status is RUNNING, Macie immediately begins to pause all processing tasks for the job.</p>
    /// <p>If you pause a one-time job and you don't resume it within 30 days, the job expires and Macie cancels the job. If you pause a recurring job when its status is RUNNING and you don't resume it within 30 days, the job run expires and Macie cancels the run. To check the expiration date, refer to the UserPausedDetails.jobExpiresAt property.</p></li>
    /// </ul>
    /// This field is required.
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new status for the job. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>CANCELLED - Stops the job permanently and cancels it. This value is valid only if the job's current status is IDLE, PAUSED, RUNNING, or USER_PAUSED.</p>
    /// <p>If you specify this value and the job's current status is RUNNING, Amazon Macie immediately begins to stop all processing tasks for the job. You can't resume or restart a job after you cancel it.</p></li>
    /// <li>
    /// <p>RUNNING - Resumes the job. This value is valid only if the job's current status is USER_PAUSED.</p>
    /// <p>If you paused the job while it was actively running and you specify this value less than 30 days after you paused the job, Macie immediately resumes processing from the point where you paused the job. Otherwise, Macie resumes the job according to the schedule and other settings for the job.</p></li>
    /// <li>
    /// <p>USER_PAUSED - Pauses the job temporarily. This value is valid only if the job's current status is IDLE, PAUSED, or RUNNING. If you specify this value and the job's current status is RUNNING, Macie immediately begins to pause all processing tasks for the job.</p>
    /// <p>If you pause a one-time job and you don't resume it within 30 days, the job expires and Macie cancels the job. If you pause a recurring job when its status is RUNNING and you don't resume it within 30 days, the job run expires and Macie cancels the run. To check the expiration date, refer to the UserPausedDetails.jobExpiresAt property.</p></li>
    /// </ul>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The new status for the job. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>CANCELLED - Stops the job permanently and cancels it. This value is valid only if the job's current status is IDLE, PAUSED, RUNNING, or USER_PAUSED.</p>
    /// <p>If you specify this value and the job's current status is RUNNING, Amazon Macie immediately begins to stop all processing tasks for the job. You can't resume or restart a job after you cancel it.</p></li>
    /// <li>
    /// <p>RUNNING - Resumes the job. This value is valid only if the job's current status is USER_PAUSED.</p>
    /// <p>If you paused the job while it was actively running and you specify this value less than 30 days after you paused the job, Macie immediately resumes processing from the point where you paused the job. Otherwise, Macie resumes the job according to the schedule and other settings for the job.</p></li>
    /// <li>
    /// <p>USER_PAUSED - Pauses the job temporarily. This value is valid only if the job's current status is IDLE, PAUSED, or RUNNING. If you specify this value and the job's current status is RUNNING, Macie immediately begins to pause all processing tasks for the job.</p>
    /// <p>If you pause a one-time job and you don't resume it within 30 days, the job expires and Macie cancels the job. If you pause a recurring job when its status is RUNNING and you don't resume it within 30 days, the job run expires and Macie cancels the run. To check the expiration date, refer to the UserPausedDetails.jobExpiresAt property.</p></li>
    /// </ul>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    /// Consumes the builder and constructs a [`UpdateClassificationJobInput`](crate::operation::update_classification_job::UpdateClassificationJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_classification_job::UpdateClassificationJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_classification_job::UpdateClassificationJobInput {
            job_id: self.job_id,
            job_status: self.job_status,
        })
    }
}
