// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartResourceEvaluationOutput {
    /// <p>A unique ResourceEvaluationId that is associated with a single execution.</p>
    pub resource_evaluation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartResourceEvaluationOutput {
    /// <p>A unique ResourceEvaluationId that is associated with a single execution.</p>
    pub fn resource_evaluation_id(&self) -> ::std::option::Option<&str> {
        self.resource_evaluation_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartResourceEvaluationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartResourceEvaluationOutput {
    /// Creates a new builder-style object to manufacture [`StartResourceEvaluationOutput`](crate::operation::start_resource_evaluation::StartResourceEvaluationOutput).
    pub fn builder() -> crate::operation::start_resource_evaluation::builders::StartResourceEvaluationOutputBuilder {
        crate::operation::start_resource_evaluation::builders::StartResourceEvaluationOutputBuilder::default()
    }
}

/// A builder for [`StartResourceEvaluationOutput`](crate::operation::start_resource_evaluation::StartResourceEvaluationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartResourceEvaluationOutputBuilder {
    pub(crate) resource_evaluation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartResourceEvaluationOutputBuilder {
    /// <p>A unique ResourceEvaluationId that is associated with a single execution.</p>
    pub fn resource_evaluation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_evaluation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique ResourceEvaluationId that is associated with a single execution.</p>
    pub fn set_resource_evaluation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_evaluation_id = input;
        self
    }
    /// <p>A unique ResourceEvaluationId that is associated with a single execution.</p>
    pub fn get_resource_evaluation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_evaluation_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartResourceEvaluationOutput`](crate::operation::start_resource_evaluation::StartResourceEvaluationOutput).
    pub fn build(self) -> crate::operation::start_resource_evaluation::StartResourceEvaluationOutput {
        crate::operation::start_resource_evaluation::StartResourceEvaluationOutput {
            resource_evaluation_id: self.resource_evaluation_id,
            _request_id: self._request_id,
        }
    }
}
