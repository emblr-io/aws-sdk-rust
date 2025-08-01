// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIdleRecommendationsOutput {
    /// <p>The token to advance to the next page of idle resource recommendations.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of objects that describe the idle resource recommendations.</p>
    pub idle_recommendations: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendation>>,
    /// <p>An array of objects that describe errors of the request.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendationError>>,
    _request_id: Option<String>,
}
impl GetIdleRecommendationsOutput {
    /// <p>The token to advance to the next page of idle resource recommendations.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of objects that describe the idle resource recommendations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.idle_recommendations.is_none()`.
    pub fn idle_recommendations(&self) -> &[crate::types::IdleRecommendation] {
        self.idle_recommendations.as_deref().unwrap_or_default()
    }
    /// <p>An array of objects that describe errors of the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::IdleRecommendationError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetIdleRecommendationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetIdleRecommendationsOutput {
    /// Creates a new builder-style object to manufacture [`GetIdleRecommendationsOutput`](crate::operation::get_idle_recommendations::GetIdleRecommendationsOutput).
    pub fn builder() -> crate::operation::get_idle_recommendations::builders::GetIdleRecommendationsOutputBuilder {
        crate::operation::get_idle_recommendations::builders::GetIdleRecommendationsOutputBuilder::default()
    }
}

/// A builder for [`GetIdleRecommendationsOutput`](crate::operation::get_idle_recommendations::GetIdleRecommendationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIdleRecommendationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) idle_recommendations: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendation>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendationError>>,
    _request_id: Option<String>,
}
impl GetIdleRecommendationsOutputBuilder {
    /// <p>The token to advance to the next page of idle resource recommendations.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of idle resource recommendations.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to advance to the next page of idle resource recommendations.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `idle_recommendations`.
    ///
    /// To override the contents of this collection use [`set_idle_recommendations`](Self::set_idle_recommendations).
    ///
    /// <p>An array of objects that describe the idle resource recommendations.</p>
    pub fn idle_recommendations(mut self, input: crate::types::IdleRecommendation) -> Self {
        let mut v = self.idle_recommendations.unwrap_or_default();
        v.push(input);
        self.idle_recommendations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the idle resource recommendations.</p>
    pub fn set_idle_recommendations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendation>>) -> Self {
        self.idle_recommendations = input;
        self
    }
    /// <p>An array of objects that describe the idle resource recommendations.</p>
    pub fn get_idle_recommendations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendation>> {
        &self.idle_recommendations
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>An array of objects that describe errors of the request.</p>
    pub fn errors(mut self, input: crate::types::IdleRecommendationError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe errors of the request.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendationError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>An array of objects that describe errors of the request.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdleRecommendationError>> {
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
    /// Consumes the builder and constructs a [`GetIdleRecommendationsOutput`](crate::operation::get_idle_recommendations::GetIdleRecommendationsOutput).
    pub fn build(self) -> crate::operation::get_idle_recommendations::GetIdleRecommendationsOutput {
        crate::operation::get_idle_recommendations::GetIdleRecommendationsOutput {
            next_token: self.next_token,
            idle_recommendations: self.idle_recommendations,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
