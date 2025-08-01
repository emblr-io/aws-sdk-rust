// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The <code>DeletePipelineResponse</code> structure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePipelineOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeletePipelineOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeletePipelineOutput {
    /// Creates a new builder-style object to manufacture [`DeletePipelineOutput`](crate::operation::delete_pipeline::DeletePipelineOutput).
    pub fn builder() -> crate::operation::delete_pipeline::builders::DeletePipelineOutputBuilder {
        crate::operation::delete_pipeline::builders::DeletePipelineOutputBuilder::default()
    }
}

/// A builder for [`DeletePipelineOutput`](crate::operation::delete_pipeline::DeletePipelineOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePipelineOutputBuilder {
    _request_id: Option<String>,
}
impl DeletePipelineOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeletePipelineOutput`](crate::operation::delete_pipeline::DeletePipelineOutput).
    pub fn build(self) -> crate::operation::delete_pipeline::DeletePipelineOutput {
        crate::operation::delete_pipeline::DeletePipelineOutput {
            _request_id: self._request_id,
        }
    }
}
