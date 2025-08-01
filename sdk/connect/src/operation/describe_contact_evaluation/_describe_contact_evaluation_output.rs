// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeContactEvaluationOutput {
    /// <p>Information about the evaluation form completed for a specific contact.</p>
    pub evaluation: ::std::option::Option<crate::types::Evaluation>,
    /// <p>Information about the evaluation form.</p>
    pub evaluation_form: ::std::option::Option<crate::types::EvaluationFormContent>,
    _request_id: Option<String>,
}
impl DescribeContactEvaluationOutput {
    /// <p>Information about the evaluation form completed for a specific contact.</p>
    pub fn evaluation(&self) -> ::std::option::Option<&crate::types::Evaluation> {
        self.evaluation.as_ref()
    }
    /// <p>Information about the evaluation form.</p>
    pub fn evaluation_form(&self) -> ::std::option::Option<&crate::types::EvaluationFormContent> {
        self.evaluation_form.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeContactEvaluationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeContactEvaluationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeContactEvaluationOutput`](crate::operation::describe_contact_evaluation::DescribeContactEvaluationOutput).
    pub fn builder() -> crate::operation::describe_contact_evaluation::builders::DescribeContactEvaluationOutputBuilder {
        crate::operation::describe_contact_evaluation::builders::DescribeContactEvaluationOutputBuilder::default()
    }
}

/// A builder for [`DescribeContactEvaluationOutput`](crate::operation::describe_contact_evaluation::DescribeContactEvaluationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeContactEvaluationOutputBuilder {
    pub(crate) evaluation: ::std::option::Option<crate::types::Evaluation>,
    pub(crate) evaluation_form: ::std::option::Option<crate::types::EvaluationFormContent>,
    _request_id: Option<String>,
}
impl DescribeContactEvaluationOutputBuilder {
    /// <p>Information about the evaluation form completed for a specific contact.</p>
    /// This field is required.
    pub fn evaluation(mut self, input: crate::types::Evaluation) -> Self {
        self.evaluation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the evaluation form completed for a specific contact.</p>
    pub fn set_evaluation(mut self, input: ::std::option::Option<crate::types::Evaluation>) -> Self {
        self.evaluation = input;
        self
    }
    /// <p>Information about the evaluation form completed for a specific contact.</p>
    pub fn get_evaluation(&self) -> &::std::option::Option<crate::types::Evaluation> {
        &self.evaluation
    }
    /// <p>Information about the evaluation form.</p>
    /// This field is required.
    pub fn evaluation_form(mut self, input: crate::types::EvaluationFormContent) -> Self {
        self.evaluation_form = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the evaluation form.</p>
    pub fn set_evaluation_form(mut self, input: ::std::option::Option<crate::types::EvaluationFormContent>) -> Self {
        self.evaluation_form = input;
        self
    }
    /// <p>Information about the evaluation form.</p>
    pub fn get_evaluation_form(&self) -> &::std::option::Option<crate::types::EvaluationFormContent> {
        &self.evaluation_form
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeContactEvaluationOutput`](crate::operation::describe_contact_evaluation::DescribeContactEvaluationOutput).
    pub fn build(self) -> crate::operation::describe_contact_evaluation::DescribeContactEvaluationOutput {
        crate::operation::describe_contact_evaluation::DescribeContactEvaluationOutput {
            evaluation: self.evaluation,
            evaluation_form: self.evaluation_form,
            _request_id: self._request_id,
        }
    }
}
