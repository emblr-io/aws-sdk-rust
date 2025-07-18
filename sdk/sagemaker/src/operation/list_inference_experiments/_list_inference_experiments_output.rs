// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInferenceExperimentsOutput {
    /// <p>List of inference experiments.</p>
    pub inference_experiments: ::std::option::Option<::std::vec::Vec<crate::types::InferenceExperimentSummary>>,
    /// <p>The token to use when calling the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInferenceExperimentsOutput {
    /// <p>List of inference experiments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inference_experiments.is_none()`.
    pub fn inference_experiments(&self) -> &[crate::types::InferenceExperimentSummary] {
        self.inference_experiments.as_deref().unwrap_or_default()
    }
    /// <p>The token to use when calling the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListInferenceExperimentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListInferenceExperimentsOutput {
    /// Creates a new builder-style object to manufacture [`ListInferenceExperimentsOutput`](crate::operation::list_inference_experiments::ListInferenceExperimentsOutput).
    pub fn builder() -> crate::operation::list_inference_experiments::builders::ListInferenceExperimentsOutputBuilder {
        crate::operation::list_inference_experiments::builders::ListInferenceExperimentsOutputBuilder::default()
    }
}

/// A builder for [`ListInferenceExperimentsOutput`](crate::operation::list_inference_experiments::ListInferenceExperimentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInferenceExperimentsOutputBuilder {
    pub(crate) inference_experiments: ::std::option::Option<::std::vec::Vec<crate::types::InferenceExperimentSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInferenceExperimentsOutputBuilder {
    /// Appends an item to `inference_experiments`.
    ///
    /// To override the contents of this collection use [`set_inference_experiments`](Self::set_inference_experiments).
    ///
    /// <p>List of inference experiments.</p>
    pub fn inference_experiments(mut self, input: crate::types::InferenceExperimentSummary) -> Self {
        let mut v = self.inference_experiments.unwrap_or_default();
        v.push(input);
        self.inference_experiments = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of inference experiments.</p>
    pub fn set_inference_experiments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InferenceExperimentSummary>>) -> Self {
        self.inference_experiments = input;
        self
    }
    /// <p>List of inference experiments.</p>
    pub fn get_inference_experiments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InferenceExperimentSummary>> {
        &self.inference_experiments
    }
    /// <p>The token to use when calling the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use when calling the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use when calling the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListInferenceExperimentsOutput`](crate::operation::list_inference_experiments::ListInferenceExperimentsOutput).
    pub fn build(self) -> crate::operation::list_inference_experiments::ListInferenceExperimentsOutput {
        crate::operation::list_inference_experiments::ListInferenceExperimentsOutput {
            inference_experiments: self.inference_experiments,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
