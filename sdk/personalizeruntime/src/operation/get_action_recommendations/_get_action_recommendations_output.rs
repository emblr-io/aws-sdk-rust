// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetActionRecommendationsOutput {
    /// <p>A list of action recommendations sorted in descending order by prediction score. There can be a maximum of 100 actions in the list. For information about action scores, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/how-action-recommendation-scoring-works.html">How action recommendation scoring works</a>.</p>
    pub action_list: ::std::option::Option<::std::vec::Vec<crate::types::PredictedAction>>,
    /// <p>The ID of the recommendation.</p>
    pub recommendation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetActionRecommendationsOutput {
    /// <p>A list of action recommendations sorted in descending order by prediction score. There can be a maximum of 100 actions in the list. For information about action scores, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/how-action-recommendation-scoring-works.html">How action recommendation scoring works</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.action_list.is_none()`.
    pub fn action_list(&self) -> &[crate::types::PredictedAction] {
        self.action_list.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the recommendation.</p>
    pub fn recommendation_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetActionRecommendationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetActionRecommendationsOutput {
    /// Creates a new builder-style object to manufacture [`GetActionRecommendationsOutput`](crate::operation::get_action_recommendations::GetActionRecommendationsOutput).
    pub fn builder() -> crate::operation::get_action_recommendations::builders::GetActionRecommendationsOutputBuilder {
        crate::operation::get_action_recommendations::builders::GetActionRecommendationsOutputBuilder::default()
    }
}

/// A builder for [`GetActionRecommendationsOutput`](crate::operation::get_action_recommendations::GetActionRecommendationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetActionRecommendationsOutputBuilder {
    pub(crate) action_list: ::std::option::Option<::std::vec::Vec<crate::types::PredictedAction>>,
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetActionRecommendationsOutputBuilder {
    /// Appends an item to `action_list`.
    ///
    /// To override the contents of this collection use [`set_action_list`](Self::set_action_list).
    ///
    /// <p>A list of action recommendations sorted in descending order by prediction score. There can be a maximum of 100 actions in the list. For information about action scores, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/how-action-recommendation-scoring-works.html">How action recommendation scoring works</a>.</p>
    pub fn action_list(mut self, input: crate::types::PredictedAction) -> Self {
        let mut v = self.action_list.unwrap_or_default();
        v.push(input);
        self.action_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of action recommendations sorted in descending order by prediction score. There can be a maximum of 100 actions in the list. For information about action scores, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/how-action-recommendation-scoring-works.html">How action recommendation scoring works</a>.</p>
    pub fn set_action_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PredictedAction>>) -> Self {
        self.action_list = input;
        self
    }
    /// <p>A list of action recommendations sorted in descending order by prediction score. There can be a maximum of 100 actions in the list. For information about action scores, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/how-action-recommendation-scoring-works.html">How action recommendation scoring works</a>.</p>
    pub fn get_action_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PredictedAction>> {
        &self.action_list
    }
    /// <p>The ID of the recommendation.</p>
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the recommendation.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The ID of the recommendation.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetActionRecommendationsOutput`](crate::operation::get_action_recommendations::GetActionRecommendationsOutput).
    pub fn build(self) -> crate::operation::get_action_recommendations::GetActionRecommendationsOutput {
        crate::operation::get_action_recommendations::GetActionRecommendationsOutput {
            action_list: self.action_list,
            recommendation_id: self.recommendation_id,
            _request_id: self._request_id,
        }
    }
}
