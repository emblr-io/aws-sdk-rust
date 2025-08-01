// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListHyperParameterTuningJobsOutput {
    /// <p>A list of <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobSummary.html">HyperParameterTuningJobSummary</a> objects that describe the tuning jobs that the <code>ListHyperParameterTuningJobs</code> request returned.</p>
    pub hyper_parameter_tuning_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningJobSummary>>,
    /// <p>If the result of this <code>ListHyperParameterTuningJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of tuning jobs, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListHyperParameterTuningJobsOutput {
    /// <p>A list of <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobSummary.html">HyperParameterTuningJobSummary</a> objects that describe the tuning jobs that the <code>ListHyperParameterTuningJobs</code> request returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hyper_parameter_tuning_job_summaries.is_none()`.
    pub fn hyper_parameter_tuning_job_summaries(&self) -> &[crate::types::HyperParameterTuningJobSummary] {
        self.hyper_parameter_tuning_job_summaries.as_deref().unwrap_or_default()
    }
    /// <p>If the result of this <code>ListHyperParameterTuningJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of tuning jobs, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListHyperParameterTuningJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListHyperParameterTuningJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListHyperParameterTuningJobsOutput`](crate::operation::list_hyper_parameter_tuning_jobs::ListHyperParameterTuningJobsOutput).
    pub fn builder() -> crate::operation::list_hyper_parameter_tuning_jobs::builders::ListHyperParameterTuningJobsOutputBuilder {
        crate::operation::list_hyper_parameter_tuning_jobs::builders::ListHyperParameterTuningJobsOutputBuilder::default()
    }
}

/// A builder for [`ListHyperParameterTuningJobsOutput`](crate::operation::list_hyper_parameter_tuning_jobs::ListHyperParameterTuningJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListHyperParameterTuningJobsOutputBuilder {
    pub(crate) hyper_parameter_tuning_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListHyperParameterTuningJobsOutputBuilder {
    /// Appends an item to `hyper_parameter_tuning_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_hyper_parameter_tuning_job_summaries`](Self::set_hyper_parameter_tuning_job_summaries).
    ///
    /// <p>A list of <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobSummary.html">HyperParameterTuningJobSummary</a> objects that describe the tuning jobs that the <code>ListHyperParameterTuningJobs</code> request returned.</p>
    pub fn hyper_parameter_tuning_job_summaries(mut self, input: crate::types::HyperParameterTuningJobSummary) -> Self {
        let mut v = self.hyper_parameter_tuning_job_summaries.unwrap_or_default();
        v.push(input);
        self.hyper_parameter_tuning_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobSummary.html">HyperParameterTuningJobSummary</a> objects that describe the tuning jobs that the <code>ListHyperParameterTuningJobs</code> request returned.</p>
    pub fn set_hyper_parameter_tuning_job_summaries(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningJobSummary>>,
    ) -> Self {
        self.hyper_parameter_tuning_job_summaries = input;
        self
    }
    /// <p>A list of <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTuningJobSummary.html">HyperParameterTuningJobSummary</a> objects that describe the tuning jobs that the <code>ListHyperParameterTuningJobs</code> request returned.</p>
    pub fn get_hyper_parameter_tuning_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HyperParameterTuningJobSummary>> {
        &self.hyper_parameter_tuning_job_summaries
    }
    /// <p>If the result of this <code>ListHyperParameterTuningJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of tuning jobs, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of this <code>ListHyperParameterTuningJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of tuning jobs, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the result of this <code>ListHyperParameterTuningJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of tuning jobs, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListHyperParameterTuningJobsOutput`](crate::operation::list_hyper_parameter_tuning_jobs::ListHyperParameterTuningJobsOutput).
    pub fn build(self) -> crate::operation::list_hyper_parameter_tuning_jobs::ListHyperParameterTuningJobsOutput {
        crate::operation::list_hyper_parameter_tuning_jobs::ListHyperParameterTuningJobsOutput {
            hyper_parameter_tuning_job_summaries: self.hyper_parameter_tuning_job_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
