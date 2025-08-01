// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of an <code>UpdateBatchPrediction</code> operation.</p>
/// <p>You can see the updated content by using the <code>GetBatchPrediction</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateBatchPredictionOutput {
    /// <p>The ID assigned to the <code>BatchPrediction</code> during creation. This value should be identical to the value of the <code>BatchPredictionId</code> in the request.</p>
    pub batch_prediction_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateBatchPredictionOutput {
    /// <p>The ID assigned to the <code>BatchPrediction</code> during creation. This value should be identical to the value of the <code>BatchPredictionId</code> in the request.</p>
    pub fn batch_prediction_id(&self) -> ::std::option::Option<&str> {
        self.batch_prediction_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateBatchPredictionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateBatchPredictionOutput {
    /// Creates a new builder-style object to manufacture [`UpdateBatchPredictionOutput`](crate::operation::update_batch_prediction::UpdateBatchPredictionOutput).
    pub fn builder() -> crate::operation::update_batch_prediction::builders::UpdateBatchPredictionOutputBuilder {
        crate::operation::update_batch_prediction::builders::UpdateBatchPredictionOutputBuilder::default()
    }
}

/// A builder for [`UpdateBatchPredictionOutput`](crate::operation::update_batch_prediction::UpdateBatchPredictionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateBatchPredictionOutputBuilder {
    pub(crate) batch_prediction_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateBatchPredictionOutputBuilder {
    /// <p>The ID assigned to the <code>BatchPrediction</code> during creation. This value should be identical to the value of the <code>BatchPredictionId</code> in the request.</p>
    pub fn batch_prediction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.batch_prediction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID assigned to the <code>BatchPrediction</code> during creation. This value should be identical to the value of the <code>BatchPredictionId</code> in the request.</p>
    pub fn set_batch_prediction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.batch_prediction_id = input;
        self
    }
    /// <p>The ID assigned to the <code>BatchPrediction</code> during creation. This value should be identical to the value of the <code>BatchPredictionId</code> in the request.</p>
    pub fn get_batch_prediction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.batch_prediction_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateBatchPredictionOutput`](crate::operation::update_batch_prediction::UpdateBatchPredictionOutput).
    pub fn build(self) -> crate::operation::update_batch_prediction::UpdateBatchPredictionOutput {
        crate::operation::update_batch_prediction::UpdateBatchPredictionOutput {
            batch_prediction_id: self.batch_prediction_id,
            _request_id: self._request_id,
        }
    }
}
