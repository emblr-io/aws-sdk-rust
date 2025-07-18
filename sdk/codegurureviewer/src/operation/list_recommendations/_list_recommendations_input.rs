// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecommendationsInput {
    /// <p>Pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that are returned per call. The default is 100.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_CodeReview.html">CodeReview</a> object.</p>
    pub code_review_arn: ::std::option::Option<::std::string::String>,
}
impl ListRecommendationsInput {
    /// <p>Pagination token.</p>
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
}
impl ListRecommendationsInput {
    /// Creates a new builder-style object to manufacture [`ListRecommendationsInput`](crate::operation::list_recommendations::ListRecommendationsInput).
    pub fn builder() -> crate::operation::list_recommendations::builders::ListRecommendationsInputBuilder {
        crate::operation::list_recommendations::builders::ListRecommendationsInputBuilder::default()
    }
}

/// A builder for [`ListRecommendationsInput`](crate::operation::list_recommendations::ListRecommendationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecommendationsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) code_review_arn: ::std::option::Option<::std::string::String>,
}
impl ListRecommendationsInputBuilder {
    /// <p>Pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Pagination token.</p>
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
    /// Consumes the builder and constructs a [`ListRecommendationsInput`](crate::operation::list_recommendations::ListRecommendationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_recommendations::ListRecommendationsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_recommendations::ListRecommendationsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            code_review_arn: self.code_review_arn,
        })
    }
}
