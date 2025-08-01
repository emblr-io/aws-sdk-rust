// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCollaborationTrainedModelExportJobsOutput {
    /// <p>The token value used to access the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The exports jobs that exist for the requested trained model in the requested collaboration.</p>
    pub collaboration_trained_model_export_jobs: ::std::vec::Vec<crate::types::CollaborationTrainedModelExportJobSummary>,
    _request_id: Option<String>,
}
impl ListCollaborationTrainedModelExportJobsOutput {
    /// <p>The token value used to access the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The exports jobs that exist for the requested trained model in the requested collaboration.</p>
    pub fn collaboration_trained_model_export_jobs(&self) -> &[crate::types::CollaborationTrainedModelExportJobSummary] {
        use std::ops::Deref;
        self.collaboration_trained_model_export_jobs.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListCollaborationTrainedModelExportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCollaborationTrainedModelExportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListCollaborationTrainedModelExportJobsOutput`](crate::operation::list_collaboration_trained_model_export_jobs::ListCollaborationTrainedModelExportJobsOutput).
    pub fn builder() -> crate::operation::list_collaboration_trained_model_export_jobs::builders::ListCollaborationTrainedModelExportJobsOutputBuilder
    {
        crate::operation::list_collaboration_trained_model_export_jobs::builders::ListCollaborationTrainedModelExportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListCollaborationTrainedModelExportJobsOutput`](crate::operation::list_collaboration_trained_model_export_jobs::ListCollaborationTrainedModelExportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCollaborationTrainedModelExportJobsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) collaboration_trained_model_export_jobs:
        ::std::option::Option<::std::vec::Vec<crate::types::CollaborationTrainedModelExportJobSummary>>,
    _request_id: Option<String>,
}
impl ListCollaborationTrainedModelExportJobsOutputBuilder {
    /// <p>The token value used to access the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token value used to access the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token value used to access the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `collaboration_trained_model_export_jobs`.
    ///
    /// To override the contents of this collection use [`set_collaboration_trained_model_export_jobs`](Self::set_collaboration_trained_model_export_jobs).
    ///
    /// <p>The exports jobs that exist for the requested trained model in the requested collaboration.</p>
    pub fn collaboration_trained_model_export_jobs(mut self, input: crate::types::CollaborationTrainedModelExportJobSummary) -> Self {
        let mut v = self.collaboration_trained_model_export_jobs.unwrap_or_default();
        v.push(input);
        self.collaboration_trained_model_export_jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The exports jobs that exist for the requested trained model in the requested collaboration.</p>
    pub fn set_collaboration_trained_model_export_jobs(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::CollaborationTrainedModelExportJobSummary>>,
    ) -> Self {
        self.collaboration_trained_model_export_jobs = input;
        self
    }
    /// <p>The exports jobs that exist for the requested trained model in the requested collaboration.</p>
    pub fn get_collaboration_trained_model_export_jobs(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::CollaborationTrainedModelExportJobSummary>> {
        &self.collaboration_trained_model_export_jobs
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListCollaborationTrainedModelExportJobsOutput`](crate::operation::list_collaboration_trained_model_export_jobs::ListCollaborationTrainedModelExportJobsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`collaboration_trained_model_export_jobs`](crate::operation::list_collaboration_trained_model_export_jobs::builders::ListCollaborationTrainedModelExportJobsOutputBuilder::collaboration_trained_model_export_jobs)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_collaboration_trained_model_export_jobs::ListCollaborationTrainedModelExportJobsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_collaboration_trained_model_export_jobs::ListCollaborationTrainedModelExportJobsOutput {
                next_token: self.next_token
                ,
                collaboration_trained_model_export_jobs: self.collaboration_trained_model_export_jobs
                    .ok_or_else(||
                        ::aws_smithy_types::error::operation::BuildError::missing_field("collaboration_trained_model_export_jobs", "collaboration_trained_model_export_jobs was not specified but it is required when building ListCollaborationTrainedModelExportJobsOutput")
                    )?
                ,
                _request_id: self._request_id,
            }
        )
    }
}
