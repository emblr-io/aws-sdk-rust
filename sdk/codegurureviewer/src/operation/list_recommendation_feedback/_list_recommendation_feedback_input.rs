// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecommendationFeedbackInput {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub code_review_arn: ::std::option::Option<::std::string::String>,
    /// <p>An Amazon Web Services user's account ID or Amazon Resource Name (ARN). Use this ID to query the recommendation feedback for a code review from that user.</p>
    /// <p>The <code>UserId</code> is an IAM principal that can be specified as an Amazon Web Services account ID or an Amazon Resource Name (ARN). For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"> Specifying a Principal</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p>
    pub user_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Used to query the recommendation feedback for a given recommendation.</p>
    pub recommendation_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListRecommendationFeedbackInput {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn code_review_arn(&self) -> ::std::option::Option<&str> {
        self.code_review_arn.as_deref()
    }
    /// <p>An Amazon Web Services user's account ID or Amazon Resource Name (ARN). Use this ID to query the recommendation feedback for a code review from that user.</p>
    /// <p>The <code>UserId</code> is an IAM principal that can be specified as an Amazon Web Services account ID or an Amazon Resource Name (ARN). For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"> Specifying a Principal</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_ids.is_none()`.
    pub fn user_ids(&self) -> &[::std::string::String] {
        self.user_ids.as_deref().unwrap_or_default()
    }
    /// <p>Used to query the recommendation feedback for a given recommendation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.recommendation_ids.is_none()`.
    pub fn recommendation_ids(&self) -> &[::std::string::String] {
        self.recommendation_ids.as_deref().unwrap_or_default()
    }
}
impl ListRecommendationFeedbackInput {
    /// Creates a new builder-style object to manufacture [`ListRecommendationFeedbackInput`](crate::operation::list_recommendation_feedback::ListRecommendationFeedbackInput).
    pub fn builder() -> crate::operation::list_recommendation_feedback::builders::ListRecommendationFeedbackInputBuilder {
        crate::operation::list_recommendation_feedback::builders::ListRecommendationFeedbackInputBuilder::default()
    }
}

/// A builder for [`ListRecommendationFeedbackInput`](crate::operation::list_recommendation_feedback::ListRecommendationFeedbackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecommendationFeedbackInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) code_review_arn: ::std::option::Option<::std::string::String>,
    pub(crate) user_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) recommendation_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListRecommendationFeedbackInputBuilder {
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    /// This field is required.
    pub fn code_review_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_review_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn set_code_review_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_review_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn get_code_review_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_review_arn
    }
    /// Appends an item to `user_ids`.
    ///
    /// To override the contents of this collection use [`set_user_ids`](Self::set_user_ids).
    ///
    /// <p>An Amazon Web Services user's account ID or Amazon Resource Name (ARN). Use this ID to query the recommendation feedback for a code review from that user.</p>
    /// <p>The <code>UserId</code> is an IAM principal that can be specified as an Amazon Web Services account ID or an Amazon Resource Name (ARN). For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"> Specifying a Principal</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p>
    pub fn user_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.user_ids.unwrap_or_default();
        v.push(input.into());
        self.user_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An Amazon Web Services user's account ID or Amazon Resource Name (ARN). Use this ID to query the recommendation feedback for a code review from that user.</p>
    /// <p>The <code>UserId</code> is an IAM principal that can be specified as an Amazon Web Services account ID or an Amazon Resource Name (ARN). For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"> Specifying a Principal</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p>
    pub fn set_user_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.user_ids = input;
        self
    }
    /// <p>An Amazon Web Services user's account ID or Amazon Resource Name (ARN). Use this ID to query the recommendation feedback for a code review from that user.</p>
    /// <p>The <code>UserId</code> is an IAM principal that can be specified as an Amazon Web Services account ID or an Amazon Resource Name (ARN). For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#Principal_specifying"> Specifying a Principal</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p>
    pub fn get_user_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.user_ids
    }
    /// Appends an item to `recommendation_ids`.
    ///
    /// To override the contents of this collection use [`set_recommendation_ids`](Self::set_recommendation_ids).
    ///
    /// <p>Used to query the recommendation feedback for a given recommendation.</p>
    pub fn recommendation_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.recommendation_ids.unwrap_or_default();
        v.push(input.into());
        self.recommendation_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Used to query the recommendation feedback for a given recommendation.</p>
    pub fn set_recommendation_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.recommendation_ids = input;
        self
    }
    /// <p>Used to query the recommendation feedback for a given recommendation.</p>
    pub fn get_recommendation_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.recommendation_ids
    }
    /// Consumes the builder and constructs a [`ListRecommendationFeedbackInput`](crate::operation::list_recommendation_feedback::ListRecommendationFeedbackInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_recommendation_feedback::ListRecommendationFeedbackInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_recommendation_feedback::ListRecommendationFeedbackInput {
            next_token: self.next_token,
            max_results: self.max_results,
            code_review_arn: self.code_review_arn,
            user_ids: self.user_ids,
            recommendation_ids: self.recommendation_ids,
        })
    }
}
