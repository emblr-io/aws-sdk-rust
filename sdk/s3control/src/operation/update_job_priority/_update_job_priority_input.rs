// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateJobPriorityInput {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the job whose priority you want to update.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The priority you want to assign to this job.</p>
    pub priority: ::std::option::Option<i32>,
}
impl UpdateJobPriorityInput {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The ID for the job whose priority you want to update.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The priority you want to assign to this job.</p>
    pub fn priority(&self) -> ::std::option::Option<i32> {
        self.priority
    }
}
impl UpdateJobPriorityInput {
    /// Creates a new builder-style object to manufacture [`UpdateJobPriorityInput`](crate::operation::update_job_priority::UpdateJobPriorityInput).
    pub fn builder() -> crate::operation::update_job_priority::builders::UpdateJobPriorityInputBuilder {
        crate::operation::update_job_priority::builders::UpdateJobPriorityInputBuilder::default()
    }
}

/// A builder for [`UpdateJobPriorityInput`](crate::operation::update_job_priority::UpdateJobPriorityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateJobPriorityInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) priority: ::std::option::Option<i32>,
}
impl UpdateJobPriorityInputBuilder {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The ID for the job whose priority you want to update.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the job whose priority you want to update.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID for the job whose priority you want to update.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The priority you want to assign to this job.</p>
    /// This field is required.
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority you want to assign to this job.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The priority you want to assign to this job.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// Consumes the builder and constructs a [`UpdateJobPriorityInput`](crate::operation::update_job_priority::UpdateJobPriorityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_job_priority::UpdateJobPriorityInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_job_priority::UpdateJobPriorityInput {
            account_id: self.account_id,
            job_id: self.job_id,
            priority: self.priority,
        })
    }
}
