// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteGremlinExplainQueryOutput {
    /// <p>A text blob containing the Gremlin explain result, as described in <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-traversal-tuning.html">Tuning Gremlin queries</a>.</p>
    pub output: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl ExecuteGremlinExplainQueryOutput {
    /// <p>A text blob containing the Gremlin explain result, as described in <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-traversal-tuning.html">Tuning Gremlin queries</a>.</p>
    pub fn output(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.output.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ExecuteGremlinExplainQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExecuteGremlinExplainQueryOutput {
    /// Creates a new builder-style object to manufacture [`ExecuteGremlinExplainQueryOutput`](crate::operation::execute_gremlin_explain_query::ExecuteGremlinExplainQueryOutput).
    pub fn builder() -> crate::operation::execute_gremlin_explain_query::builders::ExecuteGremlinExplainQueryOutputBuilder {
        crate::operation::execute_gremlin_explain_query::builders::ExecuteGremlinExplainQueryOutputBuilder::default()
    }
}

/// A builder for [`ExecuteGremlinExplainQueryOutput`](crate::operation::execute_gremlin_explain_query::ExecuteGremlinExplainQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteGremlinExplainQueryOutputBuilder {
    pub(crate) output: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl ExecuteGremlinExplainQueryOutputBuilder {
    /// <p>A text blob containing the Gremlin explain result, as described in <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-traversal-tuning.html">Tuning Gremlin queries</a>.</p>
    pub fn output(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.output = ::std::option::Option::Some(input);
        self
    }
    /// <p>A text blob containing the Gremlin explain result, as described in <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-traversal-tuning.html">Tuning Gremlin queries</a>.</p>
    pub fn set_output(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.output = input;
        self
    }
    /// <p>A text blob containing the Gremlin explain result, as described in <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-traversal-tuning.html">Tuning Gremlin queries</a>.</p>
    pub fn get_output(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.output
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ExecuteGremlinExplainQueryOutput`](crate::operation::execute_gremlin_explain_query::ExecuteGremlinExplainQueryOutput).
    pub fn build(self) -> crate::operation::execute_gremlin_explain_query::ExecuteGremlinExplainQueryOutput {
        crate::operation::execute_gremlin_explain_query::ExecuteGremlinExplainQueryOutput {
            output: self.output,
            _request_id: self._request_id,
        }
    }
}
