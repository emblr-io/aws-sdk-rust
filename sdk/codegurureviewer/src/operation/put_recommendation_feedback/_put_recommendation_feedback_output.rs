// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRecommendationFeedbackOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutRecommendationFeedbackOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutRecommendationFeedbackOutput {
    /// Creates a new builder-style object to manufacture [`PutRecommendationFeedbackOutput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackOutput).
    pub fn builder() -> crate::operation::put_recommendation_feedback::builders::PutRecommendationFeedbackOutputBuilder {
        crate::operation::put_recommendation_feedback::builders::PutRecommendationFeedbackOutputBuilder::default()
    }
}

/// A builder for [`PutRecommendationFeedbackOutput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRecommendationFeedbackOutputBuilder {
    _request_id: Option<String>,
}
impl PutRecommendationFeedbackOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutRecommendationFeedbackOutput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackOutput).
    pub fn build(self) -> crate::operation::put_recommendation_feedback::PutRecommendationFeedbackOutput {
        crate::operation::put_recommendation_feedback::PutRecommendationFeedbackOutput {
            _request_id: self._request_id,
        }
    }
}
