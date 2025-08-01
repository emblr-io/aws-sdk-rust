// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopPipelineOutput {
    /// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
    pub pipeline: ::std::option::Option<crate::types::Pipeline>,
    _request_id: Option<String>,
}
impl StopPipelineOutput {
    /// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
    pub fn pipeline(&self) -> ::std::option::Option<&crate::types::Pipeline> {
        self.pipeline.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopPipelineOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopPipelineOutput {
    /// Creates a new builder-style object to manufacture [`StopPipelineOutput`](crate::operation::stop_pipeline::StopPipelineOutput).
    pub fn builder() -> crate::operation::stop_pipeline::builders::StopPipelineOutputBuilder {
        crate::operation::stop_pipeline::builders::StopPipelineOutputBuilder::default()
    }
}

/// A builder for [`StopPipelineOutput`](crate::operation::stop_pipeline::StopPipelineOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopPipelineOutputBuilder {
    pub(crate) pipeline: ::std::option::Option<crate::types::Pipeline>,
    _request_id: Option<String>,
}
impl StopPipelineOutputBuilder {
    /// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
    pub fn pipeline(mut self, input: crate::types::Pipeline) -> Self {
        self.pipeline = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
    pub fn set_pipeline(mut self, input: ::std::option::Option<crate::types::Pipeline>) -> Self {
        self.pipeline = input;
        self
    }
    /// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
    pub fn get_pipeline(&self) -> &::std::option::Option<crate::types::Pipeline> {
        &self.pipeline
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopPipelineOutput`](crate::operation::stop_pipeline::StopPipelineOutput).
    pub fn build(self) -> crate::operation::stop_pipeline::StopPipelineOutput {
        crate::operation::stop_pipeline::StopPipelineOutput {
            pipeline: self.pipeline,
            _request_id: self._request_id,
        }
    }
}
