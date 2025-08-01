// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteGremlinProfileQueryOutput {
    /// <p>A text blob containing the Gremlin Profile result. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-profile-api.html">Gremlin profile API in Neptune</a> for details.</p>
    pub output: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl ExecuteGremlinProfileQueryOutput {
    /// <p>A text blob containing the Gremlin Profile result. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-profile-api.html">Gremlin profile API in Neptune</a> for details.</p>
    pub fn output(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.output.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ExecuteGremlinProfileQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExecuteGremlinProfileQueryOutput {
    /// Creates a new builder-style object to manufacture [`ExecuteGremlinProfileQueryOutput`](crate::operation::execute_gremlin_profile_query::ExecuteGremlinProfileQueryOutput).
    pub fn builder() -> crate::operation::execute_gremlin_profile_query::builders::ExecuteGremlinProfileQueryOutputBuilder {
        crate::operation::execute_gremlin_profile_query::builders::ExecuteGremlinProfileQueryOutputBuilder::default()
    }
}

/// A builder for [`ExecuteGremlinProfileQueryOutput`](crate::operation::execute_gremlin_profile_query::ExecuteGremlinProfileQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteGremlinProfileQueryOutputBuilder {
    pub(crate) output: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl ExecuteGremlinProfileQueryOutputBuilder {
    /// <p>A text blob containing the Gremlin Profile result. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-profile-api.html">Gremlin profile API in Neptune</a> for details.</p>
    pub fn output(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.output = ::std::option::Option::Some(input);
        self
    }
    /// <p>A text blob containing the Gremlin Profile result. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-profile-api.html">Gremlin profile API in Neptune</a> for details.</p>
    pub fn set_output(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.output = input;
        self
    }
    /// <p>A text blob containing the Gremlin Profile result. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-profile-api.html">Gremlin profile API in Neptune</a> for details.</p>
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
    /// Consumes the builder and constructs a [`ExecuteGremlinProfileQueryOutput`](crate::operation::execute_gremlin_profile_query::ExecuteGremlinProfileQueryOutput).
    pub fn build(self) -> crate::operation::execute_gremlin_profile_query::ExecuteGremlinProfileQueryOutput {
        crate::operation::execute_gremlin_profile_query::ExecuteGremlinProfileQueryOutput {
            output: self.output,
            _request_id: self._request_id,
        }
    }
}
