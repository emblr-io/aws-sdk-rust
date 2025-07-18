// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopKeyPhrasesDetectionJobInput {
    /// <p>The identifier of the key phrases detection job to stop.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl StopKeyPhrasesDetectionJobInput {
    /// <p>The identifier of the key phrases detection job to stop.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl StopKeyPhrasesDetectionJobInput {
    /// Creates a new builder-style object to manufacture [`StopKeyPhrasesDetectionJobInput`](crate::operation::stop_key_phrases_detection_job::StopKeyPhrasesDetectionJobInput).
    pub fn builder() -> crate::operation::stop_key_phrases_detection_job::builders::StopKeyPhrasesDetectionJobInputBuilder {
        crate::operation::stop_key_phrases_detection_job::builders::StopKeyPhrasesDetectionJobInputBuilder::default()
    }
}

/// A builder for [`StopKeyPhrasesDetectionJobInput`](crate::operation::stop_key_phrases_detection_job::StopKeyPhrasesDetectionJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopKeyPhrasesDetectionJobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl StopKeyPhrasesDetectionJobInputBuilder {
    /// <p>The identifier of the key phrases detection job to stop.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the key phrases detection job to stop.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier of the key phrases detection job to stop.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`StopKeyPhrasesDetectionJobInput`](crate::operation::stop_key_phrases_detection_job::StopKeyPhrasesDetectionJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_key_phrases_detection_job::StopKeyPhrasesDetectionJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::stop_key_phrases_detection_job::StopKeyPhrasesDetectionJobInput { job_id: self.job_id })
    }
}
