// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMatchmakingRuleSetsInput {
    /// <p>A list of one or more matchmaking rule set names to retrieve details for. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeMatchmakingRuleSetsInput {
    /// <p>A list of one or more matchmaking rule set names to retrieve details for. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.names.is_none()`.
    pub fn names(&self) -> &[::std::string::String] {
        self.names.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeMatchmakingRuleSetsInput {
    /// Creates a new builder-style object to manufacture [`DescribeMatchmakingRuleSetsInput`](crate::operation::describe_matchmaking_rule_sets::DescribeMatchmakingRuleSetsInput).
    pub fn builder() -> crate::operation::describe_matchmaking_rule_sets::builders::DescribeMatchmakingRuleSetsInputBuilder {
        crate::operation::describe_matchmaking_rule_sets::builders::DescribeMatchmakingRuleSetsInputBuilder::default()
    }
}

/// A builder for [`DescribeMatchmakingRuleSetsInput`](crate::operation::describe_matchmaking_rule_sets::DescribeMatchmakingRuleSetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMatchmakingRuleSetsInputBuilder {
    pub(crate) names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeMatchmakingRuleSetsInputBuilder {
    /// Appends an item to `names`.
    ///
    /// To override the contents of this collection use [`set_names`](Self::set_names).
    ///
    /// <p>A list of one or more matchmaking rule set names to retrieve details for. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.names.unwrap_or_default();
        v.push(input.into());
        self.names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of one or more matchmaking rule set names to retrieve details for. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn set_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.names = input;
        self
    }
    /// <p>A list of one or more matchmaking rule set names to retrieve details for. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn get_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.names
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeMatchmakingRuleSetsInput`](crate::operation::describe_matchmaking_rule_sets::DescribeMatchmakingRuleSetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_matchmaking_rule_sets::DescribeMatchmakingRuleSetsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_matchmaking_rule_sets::DescribeMatchmakingRuleSetsInput {
            names: self.names,
            limit: self.limit,
            next_token: self.next_token,
        })
    }
}
