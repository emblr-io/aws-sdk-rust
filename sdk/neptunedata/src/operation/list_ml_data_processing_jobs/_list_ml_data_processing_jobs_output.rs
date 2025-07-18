// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMlDataProcessingJobsOutput {
    /// <p>A page listing data processing job IDs.</p>
    pub ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListMlDataProcessingJobsOutput {
    /// <p>A page listing data processing job IDs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ids.is_none()`.
    pub fn ids(&self) -> &[::std::string::String] {
        self.ids.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListMlDataProcessingJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMlDataProcessingJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListMlDataProcessingJobsOutput`](crate::operation::list_ml_data_processing_jobs::ListMlDataProcessingJobsOutput).
    pub fn builder() -> crate::operation::list_ml_data_processing_jobs::builders::ListMlDataProcessingJobsOutputBuilder {
        crate::operation::list_ml_data_processing_jobs::builders::ListMlDataProcessingJobsOutputBuilder::default()
    }
}

/// A builder for [`ListMlDataProcessingJobsOutput`](crate::operation::list_ml_data_processing_jobs::ListMlDataProcessingJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMlDataProcessingJobsOutputBuilder {
    pub(crate) ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListMlDataProcessingJobsOutputBuilder {
    /// Appends an item to `ids`.
    ///
    /// To override the contents of this collection use [`set_ids`](Self::set_ids).
    ///
    /// <p>A page listing data processing job IDs.</p>
    pub fn ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ids.unwrap_or_default();
        v.push(input.into());
        self.ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A page listing data processing job IDs.</p>
    pub fn set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ids = input;
        self
    }
    /// <p>A page listing data processing job IDs.</p>
    pub fn get_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ids
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListMlDataProcessingJobsOutput`](crate::operation::list_ml_data_processing_jobs::ListMlDataProcessingJobsOutput).
    pub fn build(self) -> crate::operation::list_ml_data_processing_jobs::ListMlDataProcessingJobsOutput {
        crate::operation::list_ml_data_processing_jobs::ListMlDataProcessingJobsOutput {
            ids: self.ids,
            _request_id: self._request_id,
        }
    }
}
