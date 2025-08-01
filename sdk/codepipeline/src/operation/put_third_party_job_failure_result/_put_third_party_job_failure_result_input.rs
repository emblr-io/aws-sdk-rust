// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>PutThirdPartyJobFailureResult</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutThirdPartyJobFailureResultInput {
    /// <p>The ID of the job that failed. This is the same ID returned from <code>PollForThirdPartyJobs</code>.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The clientToken portion of the clientId and clientToken pair used to verify that the calling entity is allowed access to the job and its details.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Represents information about failure details.</p>
    pub failure_details: ::std::option::Option<crate::types::FailureDetails>,
}
impl PutThirdPartyJobFailureResultInput {
    /// <p>The ID of the job that failed. This is the same ID returned from <code>PollForThirdPartyJobs</code>.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The clientToken portion of the clientId and clientToken pair used to verify that the calling entity is allowed access to the job and its details.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Represents information about failure details.</p>
    pub fn failure_details(&self) -> ::std::option::Option<&crate::types::FailureDetails> {
        self.failure_details.as_ref()
    }
}
impl PutThirdPartyJobFailureResultInput {
    /// Creates a new builder-style object to manufacture [`PutThirdPartyJobFailureResultInput`](crate::operation::put_third_party_job_failure_result::PutThirdPartyJobFailureResultInput).
    pub fn builder() -> crate::operation::put_third_party_job_failure_result::builders::PutThirdPartyJobFailureResultInputBuilder {
        crate::operation::put_third_party_job_failure_result::builders::PutThirdPartyJobFailureResultInputBuilder::default()
    }
}

/// A builder for [`PutThirdPartyJobFailureResultInput`](crate::operation::put_third_party_job_failure_result::PutThirdPartyJobFailureResultInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutThirdPartyJobFailureResultInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) failure_details: ::std::option::Option<crate::types::FailureDetails>,
}
impl PutThirdPartyJobFailureResultInputBuilder {
    /// <p>The ID of the job that failed. This is the same ID returned from <code>PollForThirdPartyJobs</code>.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the job that failed. This is the same ID returned from <code>PollForThirdPartyJobs</code>.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID of the job that failed. This is the same ID returned from <code>PollForThirdPartyJobs</code>.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The clientToken portion of the clientId and clientToken pair used to verify that the calling entity is allowed access to the job and its details.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The clientToken portion of the clientId and clientToken pair used to verify that the calling entity is allowed access to the job and its details.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The clientToken portion of the clientId and clientToken pair used to verify that the calling entity is allowed access to the job and its details.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Represents information about failure details.</p>
    /// This field is required.
    pub fn failure_details(mut self, input: crate::types::FailureDetails) -> Self {
        self.failure_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents information about failure details.</p>
    pub fn set_failure_details(mut self, input: ::std::option::Option<crate::types::FailureDetails>) -> Self {
        self.failure_details = input;
        self
    }
    /// <p>Represents information about failure details.</p>
    pub fn get_failure_details(&self) -> &::std::option::Option<crate::types::FailureDetails> {
        &self.failure_details
    }
    /// Consumes the builder and constructs a [`PutThirdPartyJobFailureResultInput`](crate::operation::put_third_party_job_failure_result::PutThirdPartyJobFailureResultInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_third_party_job_failure_result::PutThirdPartyJobFailureResultInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_third_party_job_failure_result::PutThirdPartyJobFailureResultInput {
            job_id: self.job_id,
            client_token: self.client_token,
            failure_details: self.failure_details,
        })
    }
}
