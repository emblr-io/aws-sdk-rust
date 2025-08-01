// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelJobRunOutput {
    /// <p>The output contains the ID of the cancelled job run.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The output contains the virtual cluster ID for which the job run is cancelled.</p>
    pub virtual_cluster_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelJobRunOutput {
    /// <p>The output contains the ID of the cancelled job run.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The output contains the virtual cluster ID for which the job run is cancelled.</p>
    pub fn virtual_cluster_id(&self) -> ::std::option::Option<&str> {
        self.virtual_cluster_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CancelJobRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelJobRunOutput {
    /// Creates a new builder-style object to manufacture [`CancelJobRunOutput`](crate::operation::cancel_job_run::CancelJobRunOutput).
    pub fn builder() -> crate::operation::cancel_job_run::builders::CancelJobRunOutputBuilder {
        crate::operation::cancel_job_run::builders::CancelJobRunOutputBuilder::default()
    }
}

/// A builder for [`CancelJobRunOutput`](crate::operation::cancel_job_run::CancelJobRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelJobRunOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_cluster_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelJobRunOutputBuilder {
    /// <p>The output contains the ID of the cancelled job run.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output contains the ID of the cancelled job run.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The output contains the ID of the cancelled job run.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The output contains the virtual cluster ID for which the job run is cancelled.</p>
    pub fn virtual_cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output contains the virtual cluster ID for which the job run is cancelled.</p>
    pub fn set_virtual_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_cluster_id = input;
        self
    }
    /// <p>The output contains the virtual cluster ID for which the job run is cancelled.</p>
    pub fn get_virtual_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_cluster_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelJobRunOutput`](crate::operation::cancel_job_run::CancelJobRunOutput).
    pub fn build(self) -> crate::operation::cancel_job_run::CancelJobRunOutput {
        crate::operation::cancel_job_run::CancelJobRunOutput {
            id: self.id,
            virtual_cluster_id: self.virtual_cluster_id,
            _request_id: self._request_id,
        }
    }
}
