// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTransformerJobOutput {
    /// <p>Returns the unique, system-generated identifier for a transformer run.</p>
    pub transformer_job_id: ::std::string::String,
    _request_id: Option<String>,
}
impl StartTransformerJobOutput {
    /// <p>Returns the unique, system-generated identifier for a transformer run.</p>
    pub fn transformer_job_id(&self) -> &str {
        use std::ops::Deref;
        self.transformer_job_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for StartTransformerJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartTransformerJobOutput {
    /// Creates a new builder-style object to manufacture [`StartTransformerJobOutput`](crate::operation::start_transformer_job::StartTransformerJobOutput).
    pub fn builder() -> crate::operation::start_transformer_job::builders::StartTransformerJobOutputBuilder {
        crate::operation::start_transformer_job::builders::StartTransformerJobOutputBuilder::default()
    }
}

/// A builder for [`StartTransformerJobOutput`](crate::operation::start_transformer_job::StartTransformerJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTransformerJobOutputBuilder {
    pub(crate) transformer_job_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartTransformerJobOutputBuilder {
    /// <p>Returns the unique, system-generated identifier for a transformer run.</p>
    /// This field is required.
    pub fn transformer_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transformer_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the unique, system-generated identifier for a transformer run.</p>
    pub fn set_transformer_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transformer_job_id = input;
        self
    }
    /// <p>Returns the unique, system-generated identifier for a transformer run.</p>
    pub fn get_transformer_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transformer_job_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartTransformerJobOutput`](crate::operation::start_transformer_job::StartTransformerJobOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`transformer_job_id`](crate::operation::start_transformer_job::builders::StartTransformerJobOutputBuilder::transformer_job_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_transformer_job::StartTransformerJobOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_transformer_job::StartTransformerJobOutput {
            transformer_job_id: self.transformer_job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transformer_job_id",
                    "transformer_job_id was not specified but it is required when building StartTransformerJobOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
