// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLoaderJobStatusOutput {
    /// <p>The HTTP response code for the request.</p>
    pub status: ::std::string::String,
    /// <p>Status information about the load job, in a layout that could look like this:</p>
    pub payload: ::aws_smithy_types::Document,
    _request_id: Option<String>,
}
impl GetLoaderJobStatusOutput {
    /// <p>The HTTP response code for the request.</p>
    pub fn status(&self) -> &str {
        use std::ops::Deref;
        self.status.deref()
    }
    /// <p>Status information about the load job, in a layout that could look like this:</p>
    pub fn payload(&self) -> &::aws_smithy_types::Document {
        &self.payload
    }
}
impl ::aws_types::request_id::RequestId for GetLoaderJobStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLoaderJobStatusOutput {
    /// Creates a new builder-style object to manufacture [`GetLoaderJobStatusOutput`](crate::operation::get_loader_job_status::GetLoaderJobStatusOutput).
    pub fn builder() -> crate::operation::get_loader_job_status::builders::GetLoaderJobStatusOutputBuilder {
        crate::operation::get_loader_job_status::builders::GetLoaderJobStatusOutputBuilder::default()
    }
}

/// A builder for [`GetLoaderJobStatusOutput`](crate::operation::get_loader_job_status::GetLoaderJobStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLoaderJobStatusOutputBuilder {
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) payload: ::std::option::Option<::aws_smithy_types::Document>,
    _request_id: Option<String>,
}
impl GetLoaderJobStatusOutputBuilder {
    /// <p>The HTTP response code for the request.</p>
    /// This field is required.
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP response code for the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP response code for the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>Status information about the load job, in a layout that could look like this:</p>
    /// This field is required.
    pub fn payload(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status information about the load job, in a layout that could look like this:</p>
    pub fn set_payload(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.payload = input;
        self
    }
    /// <p>Status information about the load job, in a layout that could look like this:</p>
    pub fn get_payload(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.payload
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLoaderJobStatusOutput`](crate::operation::get_loader_job_status::GetLoaderJobStatusOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::operation::get_loader_job_status::builders::GetLoaderJobStatusOutputBuilder::status)
    /// - [`payload`](crate::operation::get_loader_job_status::builders::GetLoaderJobStatusOutputBuilder::payload)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_loader_job_status::GetLoaderJobStatusOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_loader_job_status::GetLoaderJobStatusOutput {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetLoaderJobStatusOutput",
                )
            })?,
            payload: self.payload.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "payload",
                    "payload was not specified but it is required when building GetLoaderJobStatusOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
