// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for ListEventBridgeRuleTemplateGroupsRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEventBridgeRuleTemplateGroupsInput {
    /// Placeholder documentation for MaxResults
    pub max_results: ::std::option::Option<i32>,
    /// A token used to retrieve the next set of results in paginated list responses.
    pub next_token: ::std::option::Option<::std::string::String>,
    /// A signal map's identifier. Can be either be its id or current name.
    pub signal_map_identifier: ::std::option::Option<::std::string::String>,
}
impl ListEventBridgeRuleTemplateGroupsInput {
    /// Placeholder documentation for MaxResults
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// A signal map's identifier. Can be either be its id or current name.
    pub fn signal_map_identifier(&self) -> ::std::option::Option<&str> {
        self.signal_map_identifier.as_deref()
    }
}
impl ListEventBridgeRuleTemplateGroupsInput {
    /// Creates a new builder-style object to manufacture [`ListEventBridgeRuleTemplateGroupsInput`](crate::operation::list_event_bridge_rule_template_groups::ListEventBridgeRuleTemplateGroupsInput).
    pub fn builder() -> crate::operation::list_event_bridge_rule_template_groups::builders::ListEventBridgeRuleTemplateGroupsInputBuilder {
        crate::operation::list_event_bridge_rule_template_groups::builders::ListEventBridgeRuleTemplateGroupsInputBuilder::default()
    }
}

/// A builder for [`ListEventBridgeRuleTemplateGroupsInput`](crate::operation::list_event_bridge_rule_template_groups::ListEventBridgeRuleTemplateGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEventBridgeRuleTemplateGroupsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) signal_map_identifier: ::std::option::Option<::std::string::String>,
}
impl ListEventBridgeRuleTemplateGroupsInputBuilder {
    /// Placeholder documentation for MaxResults
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// Placeholder documentation for MaxResults
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// Placeholder documentation for MaxResults
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// A signal map's identifier. Can be either be its id or current name.
    pub fn signal_map_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.signal_map_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// A signal map's identifier. Can be either be its id or current name.
    pub fn set_signal_map_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.signal_map_identifier = input;
        self
    }
    /// A signal map's identifier. Can be either be its id or current name.
    pub fn get_signal_map_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.signal_map_identifier
    }
    /// Consumes the builder and constructs a [`ListEventBridgeRuleTemplateGroupsInput`](crate::operation::list_event_bridge_rule_template_groups::ListEventBridgeRuleTemplateGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_event_bridge_rule_template_groups::ListEventBridgeRuleTemplateGroupsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_event_bridge_rule_template_groups::ListEventBridgeRuleTemplateGroupsInput {
                max_results: self.max_results,
                next_token: self.next_token,
                signal_map_identifier: self.signal_map_identifier,
            },
        )
    }
}
