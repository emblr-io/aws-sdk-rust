// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for DeleteEventBridgeRuleTemplateGroupRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEventBridgeRuleTemplateGroupInput {
    /// An eventbridge rule template group's identifier. Can be either be its id or current name.
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteEventBridgeRuleTemplateGroupInput {
    /// An eventbridge rule template group's identifier. Can be either be its id or current name.
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl DeleteEventBridgeRuleTemplateGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteEventBridgeRuleTemplateGroupInput`](crate::operation::delete_event_bridge_rule_template_group::DeleteEventBridgeRuleTemplateGroupInput).
    pub fn builder() -> crate::operation::delete_event_bridge_rule_template_group::builders::DeleteEventBridgeRuleTemplateGroupInputBuilder {
        crate::operation::delete_event_bridge_rule_template_group::builders::DeleteEventBridgeRuleTemplateGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteEventBridgeRuleTemplateGroupInput`](crate::operation::delete_event_bridge_rule_template_group::DeleteEventBridgeRuleTemplateGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEventBridgeRuleTemplateGroupInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteEventBridgeRuleTemplateGroupInputBuilder {
    /// An eventbridge rule template group's identifier. Can be either be its id or current name.
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// An eventbridge rule template group's identifier. Can be either be its id or current name.
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// An eventbridge rule template group's identifier. Can be either be its id or current name.
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`DeleteEventBridgeRuleTemplateGroupInput`](crate::operation::delete_event_bridge_rule_template_group::DeleteEventBridgeRuleTemplateGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_event_bridge_rule_template_group::DeleteEventBridgeRuleTemplateGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_event_bridge_rule_template_group::DeleteEventBridgeRuleTemplateGroupInput { identifier: self.identifier },
        )
    }
}
