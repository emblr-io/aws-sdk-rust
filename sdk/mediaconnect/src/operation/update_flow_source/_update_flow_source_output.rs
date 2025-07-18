// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFlowSourceOutput {
    /// <p>The ARN of the flow that you was updated.</p>
    pub flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>The details of the sources that are assigned to the flow.</p>
    pub source: ::std::option::Option<crate::types::Source>,
    _request_id: Option<String>,
}
impl UpdateFlowSourceOutput {
    /// <p>The ARN of the flow that you was updated.</p>
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
    /// <p>The details of the sources that are assigned to the flow.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::Source> {
        self.source.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateFlowSourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateFlowSourceOutput {
    /// Creates a new builder-style object to manufacture [`UpdateFlowSourceOutput`](crate::operation::update_flow_source::UpdateFlowSourceOutput).
    pub fn builder() -> crate::operation::update_flow_source::builders::UpdateFlowSourceOutputBuilder {
        crate::operation::update_flow_source::builders::UpdateFlowSourceOutputBuilder::default()
    }
}

/// A builder for [`UpdateFlowSourceOutput`](crate::operation::update_flow_source::UpdateFlowSourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFlowSourceOutputBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<crate::types::Source>,
    _request_id: Option<String>,
}
impl UpdateFlowSourceOutputBuilder {
    /// <p>The ARN of the flow that you was updated.</p>
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the flow that you was updated.</p>
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// <p>The ARN of the flow that you was updated.</p>
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// <p>The details of the sources that are assigned to the flow.</p>
    pub fn source(mut self, input: crate::types::Source) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the sources that are assigned to the flow.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::Source>) -> Self {
        self.source = input;
        self
    }
    /// <p>The details of the sources that are assigned to the flow.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::Source> {
        &self.source
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateFlowSourceOutput`](crate::operation::update_flow_source::UpdateFlowSourceOutput).
    pub fn build(self) -> crate::operation::update_flow_source::UpdateFlowSourceOutput {
        crate::operation::update_flow_source::UpdateFlowSourceOutput {
            flow_arn: self.flow_arn,
            source: self.source,
            _request_id: self._request_id,
        }
    }
}
