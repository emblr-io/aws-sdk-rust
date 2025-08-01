// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMatchmakingRuleSetOutput {
    /// <p>The newly created matchmaking rule set.</p>
    pub rule_set: ::std::option::Option<crate::types::MatchmakingRuleSet>,
    _request_id: Option<String>,
}
impl CreateMatchmakingRuleSetOutput {
    /// <p>The newly created matchmaking rule set.</p>
    pub fn rule_set(&self) -> ::std::option::Option<&crate::types::MatchmakingRuleSet> {
        self.rule_set.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateMatchmakingRuleSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateMatchmakingRuleSetOutput {
    /// Creates a new builder-style object to manufacture [`CreateMatchmakingRuleSetOutput`](crate::operation::create_matchmaking_rule_set::CreateMatchmakingRuleSetOutput).
    pub fn builder() -> crate::operation::create_matchmaking_rule_set::builders::CreateMatchmakingRuleSetOutputBuilder {
        crate::operation::create_matchmaking_rule_set::builders::CreateMatchmakingRuleSetOutputBuilder::default()
    }
}

/// A builder for [`CreateMatchmakingRuleSetOutput`](crate::operation::create_matchmaking_rule_set::CreateMatchmakingRuleSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMatchmakingRuleSetOutputBuilder {
    pub(crate) rule_set: ::std::option::Option<crate::types::MatchmakingRuleSet>,
    _request_id: Option<String>,
}
impl CreateMatchmakingRuleSetOutputBuilder {
    /// <p>The newly created matchmaking rule set.</p>
    /// This field is required.
    pub fn rule_set(mut self, input: crate::types::MatchmakingRuleSet) -> Self {
        self.rule_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>The newly created matchmaking rule set.</p>
    pub fn set_rule_set(mut self, input: ::std::option::Option<crate::types::MatchmakingRuleSet>) -> Self {
        self.rule_set = input;
        self
    }
    /// <p>The newly created matchmaking rule set.</p>
    pub fn get_rule_set(&self) -> &::std::option::Option<crate::types::MatchmakingRuleSet> {
        &self.rule_set
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateMatchmakingRuleSetOutput`](crate::operation::create_matchmaking_rule_set::CreateMatchmakingRuleSetOutput).
    pub fn build(self) -> crate::operation::create_matchmaking_rule_set::CreateMatchmakingRuleSetOutput {
        crate::operation::create_matchmaking_rule_set::CreateMatchmakingRuleSetOutput {
            rule_set: self.rule_set,
            _request_id: self._request_id,
        }
    }
}
