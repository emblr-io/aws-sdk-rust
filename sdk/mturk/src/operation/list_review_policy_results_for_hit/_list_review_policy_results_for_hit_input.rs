// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListReviewPolicyResultsForHitInput {
    /// <p>The unique identifier of the HIT to retrieve review results for.</p>
    pub hit_id: ::std::option::Option<::std::string::String>,
    /// <p>The Policy Level(s) to retrieve review results for - HIT or Assignment. If omitted, the default behavior is to retrieve all data for both policy levels. For a list of all the described policies, see Review Policies.</p>
    pub policy_levels: ::std::option::Option<::std::vec::Vec<crate::types::ReviewPolicyLevel>>,
    /// <p>Specify if the operation should retrieve a list of the actions taken executing the Review Policies and their outcomes.</p>
    pub retrieve_actions: ::std::option::Option<bool>,
    /// <p>Specify if the operation should retrieve a list of the results computed by the Review Policies.</p>
    pub retrieve_results: ::std::option::Option<bool>,
    /// <p>Pagination token</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Limit the number of results returned.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListReviewPolicyResultsForHitInput {
    /// <p>The unique identifier of the HIT to retrieve review results for.</p>
    pub fn hit_id(&self) -> ::std::option::Option<&str> {
        self.hit_id.as_deref()
    }
    /// <p>The Policy Level(s) to retrieve review results for - HIT or Assignment. If omitted, the default behavior is to retrieve all data for both policy levels. For a list of all the described policies, see Review Policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_levels.is_none()`.
    pub fn policy_levels(&self) -> &[crate::types::ReviewPolicyLevel] {
        self.policy_levels.as_deref().unwrap_or_default()
    }
    /// <p>Specify if the operation should retrieve a list of the actions taken executing the Review Policies and their outcomes.</p>
    pub fn retrieve_actions(&self) -> ::std::option::Option<bool> {
        self.retrieve_actions
    }
    /// <p>Specify if the operation should retrieve a list of the results computed by the Review Policies.</p>
    pub fn retrieve_results(&self) -> ::std::option::Option<bool> {
        self.retrieve_results
    }
    /// <p>Pagination token</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Limit the number of results returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListReviewPolicyResultsForHitInput {
    /// Creates a new builder-style object to manufacture [`ListReviewPolicyResultsForHitInput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitInput).
    pub fn builder() -> crate::operation::list_review_policy_results_for_hit::builders::ListReviewPolicyResultsForHitInputBuilder {
        crate::operation::list_review_policy_results_for_hit::builders::ListReviewPolicyResultsForHitInputBuilder::default()
    }
}

/// A builder for [`ListReviewPolicyResultsForHitInput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListReviewPolicyResultsForHitInputBuilder {
    pub(crate) hit_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_levels: ::std::option::Option<::std::vec::Vec<crate::types::ReviewPolicyLevel>>,
    pub(crate) retrieve_actions: ::std::option::Option<bool>,
    pub(crate) retrieve_results: ::std::option::Option<bool>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListReviewPolicyResultsForHitInputBuilder {
    /// <p>The unique identifier of the HIT to retrieve review results for.</p>
    /// This field is required.
    pub fn hit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the HIT to retrieve review results for.</p>
    pub fn set_hit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hit_id = input;
        self
    }
    /// <p>The unique identifier of the HIT to retrieve review results for.</p>
    pub fn get_hit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hit_id
    }
    /// Appends an item to `policy_levels`.
    ///
    /// To override the contents of this collection use [`set_policy_levels`](Self::set_policy_levels).
    ///
    /// <p>The Policy Level(s) to retrieve review results for - HIT or Assignment. If omitted, the default behavior is to retrieve all data for both policy levels. For a list of all the described policies, see Review Policies.</p>
    pub fn policy_levels(mut self, input: crate::types::ReviewPolicyLevel) -> Self {
        let mut v = self.policy_levels.unwrap_or_default();
        v.push(input);
        self.policy_levels = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Policy Level(s) to retrieve review results for - HIT or Assignment. If omitted, the default behavior is to retrieve all data for both policy levels. For a list of all the described policies, see Review Policies.</p>
    pub fn set_policy_levels(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReviewPolicyLevel>>) -> Self {
        self.policy_levels = input;
        self
    }
    /// <p>The Policy Level(s) to retrieve review results for - HIT or Assignment. If omitted, the default behavior is to retrieve all data for both policy levels. For a list of all the described policies, see Review Policies.</p>
    pub fn get_policy_levels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReviewPolicyLevel>> {
        &self.policy_levels
    }
    /// <p>Specify if the operation should retrieve a list of the actions taken executing the Review Policies and their outcomes.</p>
    pub fn retrieve_actions(mut self, input: bool) -> Self {
        self.retrieve_actions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify if the operation should retrieve a list of the actions taken executing the Review Policies and their outcomes.</p>
    pub fn set_retrieve_actions(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retrieve_actions = input;
        self
    }
    /// <p>Specify if the operation should retrieve a list of the actions taken executing the Review Policies and their outcomes.</p>
    pub fn get_retrieve_actions(&self) -> &::std::option::Option<bool> {
        &self.retrieve_actions
    }
    /// <p>Specify if the operation should retrieve a list of the results computed by the Review Policies.</p>
    pub fn retrieve_results(mut self, input: bool) -> Self {
        self.retrieve_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify if the operation should retrieve a list of the results computed by the Review Policies.</p>
    pub fn set_retrieve_results(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retrieve_results = input;
        self
    }
    /// <p>Specify if the operation should retrieve a list of the results computed by the Review Policies.</p>
    pub fn get_retrieve_results(&self) -> &::std::option::Option<bool> {
        &self.retrieve_results
    }
    /// <p>Pagination token</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pagination token</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Pagination token</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Limit the number of results returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Limit the number of results returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Limit the number of results returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListReviewPolicyResultsForHitInput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitInput {
            hit_id: self.hit_id,
            policy_levels: self.policy_levels,
            retrieve_actions: self.retrieve_actions,
            retrieve_results: self.retrieve_results,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
