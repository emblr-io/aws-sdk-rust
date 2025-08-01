// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecommendersInput {
    /// <p>The Amazon Resource Name (ARN) of the Domain dataset group to list the recommenders for. When a Domain dataset group is not specified, all the recommenders associated with the account are listed.</p>
    pub dataset_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>A token returned from the previous call to <code>ListRecommenders</code> for getting the next set of recommenders (if they exist).</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of recommenders to return.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListRecommendersInput {
    /// <p>The Amazon Resource Name (ARN) of the Domain dataset group to list the recommenders for. When a Domain dataset group is not specified, all the recommenders associated with the account are listed.</p>
    pub fn dataset_group_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_group_arn.as_deref()
    }
    /// <p>A token returned from the previous call to <code>ListRecommenders</code> for getting the next set of recommenders (if they exist).</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of recommenders to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListRecommendersInput {
    /// Creates a new builder-style object to manufacture [`ListRecommendersInput`](crate::operation::list_recommenders::ListRecommendersInput).
    pub fn builder() -> crate::operation::list_recommenders::builders::ListRecommendersInputBuilder {
        crate::operation::list_recommenders::builders::ListRecommendersInputBuilder::default()
    }
}

/// A builder for [`ListRecommendersInput`](crate::operation::list_recommenders::ListRecommendersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecommendersInputBuilder {
    pub(crate) dataset_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListRecommendersInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Domain dataset group to list the recommenders for. When a Domain dataset group is not specified, all the recommenders associated with the account are listed.</p>
    pub fn dataset_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Domain dataset group to list the recommenders for. When a Domain dataset group is not specified, all the recommenders associated with the account are listed.</p>
    pub fn set_dataset_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Domain dataset group to list the recommenders for. When a Domain dataset group is not specified, all the recommenders associated with the account are listed.</p>
    pub fn get_dataset_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_group_arn
    }
    /// <p>A token returned from the previous call to <code>ListRecommenders</code> for getting the next set of recommenders (if they exist).</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token returned from the previous call to <code>ListRecommenders</code> for getting the next set of recommenders (if they exist).</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token returned from the previous call to <code>ListRecommenders</code> for getting the next set of recommenders (if they exist).</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of recommenders to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of recommenders to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of recommenders to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListRecommendersInput`](crate::operation::list_recommenders::ListRecommendersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_recommenders::ListRecommendersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_recommenders::ListRecommendersInput {
            dataset_group_arn: self.dataset_group_arn,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
