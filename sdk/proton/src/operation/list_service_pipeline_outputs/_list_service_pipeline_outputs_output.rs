// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServicePipelineOutputsOutput {
    /// <p>A token that indicates the location of the next output in the array of outputs, after the current requested list of outputs.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of service pipeline Infrastructure as Code (IaC) outputs.</p>
    pub outputs: ::std::vec::Vec<crate::types::Output>,
    _request_id: Option<String>,
}
impl ListServicePipelineOutputsOutput {
    /// <p>A token that indicates the location of the next output in the array of outputs, after the current requested list of outputs.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of service pipeline Infrastructure as Code (IaC) outputs.</p>
    pub fn outputs(&self) -> &[crate::types::Output] {
        use std::ops::Deref;
        self.outputs.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListServicePipelineOutputsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListServicePipelineOutputsOutput {
    /// Creates a new builder-style object to manufacture [`ListServicePipelineOutputsOutput`](crate::operation::list_service_pipeline_outputs::ListServicePipelineOutputsOutput).
    pub fn builder() -> crate::operation::list_service_pipeline_outputs::builders::ListServicePipelineOutputsOutputBuilder {
        crate::operation::list_service_pipeline_outputs::builders::ListServicePipelineOutputsOutputBuilder::default()
    }
}

/// A builder for [`ListServicePipelineOutputsOutput`](crate::operation::list_service_pipeline_outputs::ListServicePipelineOutputsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServicePipelineOutputsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) outputs: ::std::option::Option<::std::vec::Vec<crate::types::Output>>,
    _request_id: Option<String>,
}
impl ListServicePipelineOutputsOutputBuilder {
    /// <p>A token that indicates the location of the next output in the array of outputs, after the current requested list of outputs.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates the location of the next output in the array of outputs, after the current requested list of outputs.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates the location of the next output in the array of outputs, after the current requested list of outputs.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `outputs`.
    ///
    /// To override the contents of this collection use [`set_outputs`](Self::set_outputs).
    ///
    /// <p>An array of service pipeline Infrastructure as Code (IaC) outputs.</p>
    pub fn outputs(mut self, input: crate::types::Output) -> Self {
        let mut v = self.outputs.unwrap_or_default();
        v.push(input);
        self.outputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of service pipeline Infrastructure as Code (IaC) outputs.</p>
    pub fn set_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Output>>) -> Self {
        self.outputs = input;
        self
    }
    /// <p>An array of service pipeline Infrastructure as Code (IaC) outputs.</p>
    pub fn get_outputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Output>> {
        &self.outputs
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListServicePipelineOutputsOutput`](crate::operation::list_service_pipeline_outputs::ListServicePipelineOutputsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`outputs`](crate::operation::list_service_pipeline_outputs::builders::ListServicePipelineOutputsOutputBuilder::outputs)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_service_pipeline_outputs::ListServicePipelineOutputsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_service_pipeline_outputs::ListServicePipelineOutputsOutput {
            next_token: self.next_token,
            outputs: self.outputs.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "outputs",
                    "outputs was not specified but it is required when building ListServicePipelineOutputsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
