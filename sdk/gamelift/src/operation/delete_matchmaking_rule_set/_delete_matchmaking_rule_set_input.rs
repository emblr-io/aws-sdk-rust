// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMatchmakingRuleSetInput {
    /// <p>A unique identifier for the matchmaking rule set to be deleted. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteMatchmakingRuleSetInput {
    /// <p>A unique identifier for the matchmaking rule set to be deleted. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteMatchmakingRuleSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteMatchmakingRuleSetInput`](crate::operation::delete_matchmaking_rule_set::DeleteMatchmakingRuleSetInput).
    pub fn builder() -> crate::operation::delete_matchmaking_rule_set::builders::DeleteMatchmakingRuleSetInputBuilder {
        crate::operation::delete_matchmaking_rule_set::builders::DeleteMatchmakingRuleSetInputBuilder::default()
    }
}

/// A builder for [`DeleteMatchmakingRuleSetInput`](crate::operation::delete_matchmaking_rule_set::DeleteMatchmakingRuleSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMatchmakingRuleSetInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteMatchmakingRuleSetInputBuilder {
    /// <p>A unique identifier for the matchmaking rule set to be deleted. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the matchmaking rule set to be deleted. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A unique identifier for the matchmaking rule set to be deleted. (Note: The rule set name is different from the optional "name" field in the rule set body.) You can use either the rule set name or ARN value.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteMatchmakingRuleSetInput`](crate::operation::delete_matchmaking_rule_set::DeleteMatchmakingRuleSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_matchmaking_rule_set::DeleteMatchmakingRuleSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_matchmaking_rule_set::DeleteMatchmakingRuleSetInput { name: self.name })
    }
}
