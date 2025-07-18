// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRecommendationFeedbackInput {
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub code_review_arn: ::std::option::Option<::std::string::String>,
    /// <p>The recommendation ID that can be used to track the provided recommendations and then to collect the feedback.</p>
    pub recommendation_id: ::std::option::Option<::std::string::String>,
    /// <p>List for storing reactions. Reactions are utf-8 text code for emojis. If you send an empty list it clears all your feedback.</p>
    pub reactions: ::std::option::Option<::std::vec::Vec<crate::types::Reaction>>,
}
impl PutRecommendationFeedbackInput {
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub fn code_review_arn(&self) -> ::std::option::Option<&str> {
        self.code_review_arn.as_deref()
    }
    /// <p>The recommendation ID that can be used to track the provided recommendations and then to collect the feedback.</p>
    pub fn recommendation_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_id.as_deref()
    }
    /// <p>List for storing reactions. Reactions are utf-8 text code for emojis. If you send an empty list it clears all your feedback.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reactions.is_none()`.
    pub fn reactions(&self) -> &[crate::types::Reaction] {
        self.reactions.as_deref().unwrap_or_default()
    }
}
impl PutRecommendationFeedbackInput {
    /// Creates a new builder-style object to manufacture [`PutRecommendationFeedbackInput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackInput).
    pub fn builder() -> crate::operation::put_recommendation_feedback::builders::PutRecommendationFeedbackInputBuilder {
        crate::operation::put_recommendation_feedback::builders::PutRecommendationFeedbackInputBuilder::default()
    }
}

/// A builder for [`PutRecommendationFeedbackInput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRecommendationFeedbackInputBuilder {
    pub(crate) code_review_arn: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    pub(crate) reactions: ::std::option::Option<::std::vec::Vec<crate::types::Reaction>>,
}
impl PutRecommendationFeedbackInputBuilder {
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
    /// <p>The recommendation ID that can be used to track the provided recommendations and then to collect the feedback.</p>
    /// This field is required.
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recommendation ID that can be used to track the provided recommendations and then to collect the feedback.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The recommendation ID that can be used to track the provided recommendations and then to collect the feedback.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    /// Appends an item to `reactions`.
    ///
    /// To override the contents of this collection use [`set_reactions`](Self::set_reactions).
    ///
    /// <p>List for storing reactions. Reactions are utf-8 text code for emojis. If you send an empty list it clears all your feedback.</p>
    pub fn reactions(mut self, input: crate::types::Reaction) -> Self {
        let mut v = self.reactions.unwrap_or_default();
        v.push(input);
        self.reactions = ::std::option::Option::Some(v);
        self
    }
    /// <p>List for storing reactions. Reactions are utf-8 text code for emojis. If you send an empty list it clears all your feedback.</p>
    pub fn set_reactions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Reaction>>) -> Self {
        self.reactions = input;
        self
    }
    /// <p>List for storing reactions. Reactions are utf-8 text code for emojis. If you send an empty list it clears all your feedback.</p>
    pub fn get_reactions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Reaction>> {
        &self.reactions
    }
    /// Consumes the builder and constructs a [`PutRecommendationFeedbackInput`](crate::operation::put_recommendation_feedback::PutRecommendationFeedbackInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_recommendation_feedback::PutRecommendationFeedbackInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_recommendation_feedback::PutRecommendationFeedbackInput {
            code_review_arn: self.code_review_arn,
            recommendation_id: self.recommendation_id,
            reactions: self.reactions,
        })
    }
}
