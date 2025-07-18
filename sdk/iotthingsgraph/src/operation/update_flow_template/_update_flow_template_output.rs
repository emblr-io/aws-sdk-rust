// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFlowTemplateOutput {
    /// <p>An object containing summary information about the updated workflow.</p>
    pub summary: ::std::option::Option<crate::types::FlowTemplateSummary>,
    _request_id: Option<String>,
}
impl UpdateFlowTemplateOutput {
    /// <p>An object containing summary information about the updated workflow.</p>
    pub fn summary(&self) -> ::std::option::Option<&crate::types::FlowTemplateSummary> {
        self.summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateFlowTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateFlowTemplateOutput {
    /// Creates a new builder-style object to manufacture [`UpdateFlowTemplateOutput`](crate::operation::update_flow_template::UpdateFlowTemplateOutput).
    pub fn builder() -> crate::operation::update_flow_template::builders::UpdateFlowTemplateOutputBuilder {
        crate::operation::update_flow_template::builders::UpdateFlowTemplateOutputBuilder::default()
    }
}

/// A builder for [`UpdateFlowTemplateOutput`](crate::operation::update_flow_template::UpdateFlowTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFlowTemplateOutputBuilder {
    pub(crate) summary: ::std::option::Option<crate::types::FlowTemplateSummary>,
    _request_id: Option<String>,
}
impl UpdateFlowTemplateOutputBuilder {
    /// <p>An object containing summary information about the updated workflow.</p>
    pub fn summary(mut self, input: crate::types::FlowTemplateSummary) -> Self {
        self.summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object containing summary information about the updated workflow.</p>
    pub fn set_summary(mut self, input: ::std::option::Option<crate::types::FlowTemplateSummary>) -> Self {
        self.summary = input;
        self
    }
    /// <p>An object containing summary information about the updated workflow.</p>
    pub fn get_summary(&self) -> &::std::option::Option<crate::types::FlowTemplateSummary> {
        &self.summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateFlowTemplateOutput`](crate::operation::update_flow_template::UpdateFlowTemplateOutput).
    pub fn build(self) -> crate::operation::update_flow_template::UpdateFlowTemplateOutput {
        crate::operation::update_flow_template::UpdateFlowTemplateOutput {
            summary: self.summary,
            _request_id: self._request_id,
        }
    }
}
