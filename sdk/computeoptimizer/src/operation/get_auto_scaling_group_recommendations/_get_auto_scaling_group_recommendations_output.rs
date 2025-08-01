// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAutoScalingGroupRecommendationsOutput {
    /// <p>The token to use to advance to the next page of Auto Scaling group recommendations.</p>
    /// <p>This value is null when there are no more pages of Auto Scaling group recommendations to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of objects that describe Auto Scaling group recommendations.</p>
    pub auto_scaling_group_recommendations: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroupRecommendation>>,
    /// <p>An array of objects that describe errors of the request.</p>
    /// <p>For example, an error is returned if you request recommendations for an unsupported Auto Scaling group.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::GetRecommendationError>>,
    _request_id: Option<String>,
}
impl GetAutoScalingGroupRecommendationsOutput {
    /// <p>The token to use to advance to the next page of Auto Scaling group recommendations.</p>
    /// <p>This value is null when there are no more pages of Auto Scaling group recommendations to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of objects that describe Auto Scaling group recommendations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.auto_scaling_group_recommendations.is_none()`.
    pub fn auto_scaling_group_recommendations(&self) -> &[crate::types::AutoScalingGroupRecommendation] {
        self.auto_scaling_group_recommendations.as_deref().unwrap_or_default()
    }
    /// <p>An array of objects that describe errors of the request.</p>
    /// <p>For example, an error is returned if you request recommendations for an unsupported Auto Scaling group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::GetRecommendationError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetAutoScalingGroupRecommendationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAutoScalingGroupRecommendationsOutput {
    /// Creates a new builder-style object to manufacture [`GetAutoScalingGroupRecommendationsOutput`](crate::operation::get_auto_scaling_group_recommendations::GetAutoScalingGroupRecommendationsOutput).
    pub fn builder() -> crate::operation::get_auto_scaling_group_recommendations::builders::GetAutoScalingGroupRecommendationsOutputBuilder {
        crate::operation::get_auto_scaling_group_recommendations::builders::GetAutoScalingGroupRecommendationsOutputBuilder::default()
    }
}

/// A builder for [`GetAutoScalingGroupRecommendationsOutput`](crate::operation::get_auto_scaling_group_recommendations::GetAutoScalingGroupRecommendationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAutoScalingGroupRecommendationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_recommendations: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroupRecommendation>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::GetRecommendationError>>,
    _request_id: Option<String>,
}
impl GetAutoScalingGroupRecommendationsOutputBuilder {
    /// <p>The token to use to advance to the next page of Auto Scaling group recommendations.</p>
    /// <p>This value is null when there are no more pages of Auto Scaling group recommendations to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to advance to the next page of Auto Scaling group recommendations.</p>
    /// <p>This value is null when there are no more pages of Auto Scaling group recommendations to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to advance to the next page of Auto Scaling group recommendations.</p>
    /// <p>This value is null when there are no more pages of Auto Scaling group recommendations to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `auto_scaling_group_recommendations`.
    ///
    /// To override the contents of this collection use [`set_auto_scaling_group_recommendations`](Self::set_auto_scaling_group_recommendations).
    ///
    /// <p>An array of objects that describe Auto Scaling group recommendations.</p>
    pub fn auto_scaling_group_recommendations(mut self, input: crate::types::AutoScalingGroupRecommendation) -> Self {
        let mut v = self.auto_scaling_group_recommendations.unwrap_or_default();
        v.push(input);
        self.auto_scaling_group_recommendations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe Auto Scaling group recommendations.</p>
    pub fn set_auto_scaling_group_recommendations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroupRecommendation>>,
    ) -> Self {
        self.auto_scaling_group_recommendations = input;
        self
    }
    /// <p>An array of objects that describe Auto Scaling group recommendations.</p>
    pub fn get_auto_scaling_group_recommendations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroupRecommendation>> {
        &self.auto_scaling_group_recommendations
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>An array of objects that describe errors of the request.</p>
    /// <p>For example, an error is returned if you request recommendations for an unsupported Auto Scaling group.</p>
    pub fn errors(mut self, input: crate::types::GetRecommendationError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe errors of the request.</p>
    /// <p>For example, an error is returned if you request recommendations for an unsupported Auto Scaling group.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GetRecommendationError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>An array of objects that describe errors of the request.</p>
    /// <p>For example, an error is returned if you request recommendations for an unsupported Auto Scaling group.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GetRecommendationError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAutoScalingGroupRecommendationsOutput`](crate::operation::get_auto_scaling_group_recommendations::GetAutoScalingGroupRecommendationsOutput).
    pub fn build(self) -> crate::operation::get_auto_scaling_group_recommendations::GetAutoScalingGroupRecommendationsOutput {
        crate::operation::get_auto_scaling_group_recommendations::GetAutoScalingGroupRecommendationsOutput {
            next_token: self.next_token,
            auto_scaling_group_recommendations: self.auto_scaling_group_recommendations,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
