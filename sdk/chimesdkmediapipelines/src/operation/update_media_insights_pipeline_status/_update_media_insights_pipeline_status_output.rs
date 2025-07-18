// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMediaInsightsPipelineStatusOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateMediaInsightsPipelineStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateMediaInsightsPipelineStatusOutput {
    /// Creates a new builder-style object to manufacture [`UpdateMediaInsightsPipelineStatusOutput`](crate::operation::update_media_insights_pipeline_status::UpdateMediaInsightsPipelineStatusOutput).
    pub fn builder() -> crate::operation::update_media_insights_pipeline_status::builders::UpdateMediaInsightsPipelineStatusOutputBuilder {
        crate::operation::update_media_insights_pipeline_status::builders::UpdateMediaInsightsPipelineStatusOutputBuilder::default()
    }
}

/// A builder for [`UpdateMediaInsightsPipelineStatusOutput`](crate::operation::update_media_insights_pipeline_status::UpdateMediaInsightsPipelineStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMediaInsightsPipelineStatusOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateMediaInsightsPipelineStatusOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateMediaInsightsPipelineStatusOutput`](crate::operation::update_media_insights_pipeline_status::UpdateMediaInsightsPipelineStatusOutput).
    pub fn build(self) -> crate::operation::update_media_insights_pipeline_status::UpdateMediaInsightsPipelineStatusOutput {
        crate::operation::update_media_insights_pipeline_status::UpdateMediaInsightsPipelineStatusOutput {
            _request_id: self._request_id,
        }
    }
}
