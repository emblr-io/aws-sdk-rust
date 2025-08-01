// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about the policy generation status and properties.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PolicyGeneration {
    /// <p>The <code>JobId</code> that is returned by the <code>StartPolicyGeneration</code> operation. The <code>JobId</code> can be used with <code>GetGeneratedPolicy</code> to retrieve the generated policies or used with <code>CancelPolicyGeneration</code> to cancel the policy generation request.</p>
    pub job_id: ::std::string::String,
    /// <p>The ARN of the IAM entity (user or role) for which you are generating a policy.</p>
    pub principal_arn: ::std::string::String,
    /// <p>The status of the policy generation request.</p>
    pub status: crate::types::JobStatus,
    /// <p>A timestamp of when the policy generation started.</p>
    pub started_on: ::aws_smithy_types::DateTime,
    /// <p>A timestamp of when the policy generation was completed.</p>
    pub completed_on: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PolicyGeneration {
    /// <p>The <code>JobId</code> that is returned by the <code>StartPolicyGeneration</code> operation. The <code>JobId</code> can be used with <code>GetGeneratedPolicy</code> to retrieve the generated policies or used with <code>CancelPolicyGeneration</code> to cancel the policy generation request.</p>
    pub fn job_id(&self) -> &str {
        use std::ops::Deref;
        self.job_id.deref()
    }
    /// <p>The ARN of the IAM entity (user or role) for which you are generating a policy.</p>
    pub fn principal_arn(&self) -> &str {
        use std::ops::Deref;
        self.principal_arn.deref()
    }
    /// <p>The status of the policy generation request.</p>
    pub fn status(&self) -> &crate::types::JobStatus {
        &self.status
    }
    /// <p>A timestamp of when the policy generation started.</p>
    pub fn started_on(&self) -> &::aws_smithy_types::DateTime {
        &self.started_on
    }
    /// <p>A timestamp of when the policy generation was completed.</p>
    pub fn completed_on(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completed_on.as_ref()
    }
}
impl PolicyGeneration {
    /// Creates a new builder-style object to manufacture [`PolicyGeneration`](crate::types::PolicyGeneration).
    pub fn builder() -> crate::types::builders::PolicyGenerationBuilder {
        crate::types::builders::PolicyGenerationBuilder::default()
    }
}

/// A builder for [`PolicyGeneration`](crate::types::PolicyGeneration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PolicyGenerationBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) started_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completed_on: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PolicyGenerationBuilder {
    /// <p>The <code>JobId</code> that is returned by the <code>StartPolicyGeneration</code> operation. The <code>JobId</code> can be used with <code>GetGeneratedPolicy</code> to retrieve the generated policies or used with <code>CancelPolicyGeneration</code> to cancel the policy generation request.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>JobId</code> that is returned by the <code>StartPolicyGeneration</code> operation. The <code>JobId</code> can be used with <code>GetGeneratedPolicy</code> to retrieve the generated policies or used with <code>CancelPolicyGeneration</code> to cancel the policy generation request.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The <code>JobId</code> that is returned by the <code>StartPolicyGeneration</code> operation. The <code>JobId</code> can be used with <code>GetGeneratedPolicy</code> to retrieve the generated policies or used with <code>CancelPolicyGeneration</code> to cancel the policy generation request.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The ARN of the IAM entity (user or role) for which you are generating a policy.</p>
    /// This field is required.
    pub fn principal_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM entity (user or role) for which you are generating a policy.</p>
    pub fn set_principal_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_arn = input;
        self
    }
    /// <p>The ARN of the IAM entity (user or role) for which you are generating a policy.</p>
    pub fn get_principal_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_arn
    }
    /// <p>The status of the policy generation request.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::JobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the policy generation request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the policy generation request.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.status
    }
    /// <p>A timestamp of when the policy generation started.</p>
    /// This field is required.
    pub fn started_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp of when the policy generation started.</p>
    pub fn set_started_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_on = input;
        self
    }
    /// <p>A timestamp of when the policy generation started.</p>
    pub fn get_started_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_on
    }
    /// <p>A timestamp of when the policy generation was completed.</p>
    pub fn completed_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completed_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp of when the policy generation was completed.</p>
    pub fn set_completed_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completed_on = input;
        self
    }
    /// <p>A timestamp of when the policy generation was completed.</p>
    pub fn get_completed_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completed_on
    }
    /// Consumes the builder and constructs a [`PolicyGeneration`](crate::types::PolicyGeneration).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_id`](crate::types::builders::PolicyGenerationBuilder::job_id)
    /// - [`principal_arn`](crate::types::builders::PolicyGenerationBuilder::principal_arn)
    /// - [`status`](crate::types::builders::PolicyGenerationBuilder::status)
    /// - [`started_on`](crate::types::builders::PolicyGenerationBuilder::started_on)
    pub fn build(self) -> ::std::result::Result<crate::types::PolicyGeneration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PolicyGeneration {
            job_id: self.job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_id",
                    "job_id was not specified but it is required when building PolicyGeneration",
                )
            })?,
            principal_arn: self.principal_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "principal_arn",
                    "principal_arn was not specified but it is required when building PolicyGeneration",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building PolicyGeneration",
                )
            })?,
            started_on: self.started_on.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "started_on",
                    "started_on was not specified but it is required when building PolicyGeneration",
                )
            })?,
            completed_on: self.completed_on,
        })
    }
}
