// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This action must be set if <code>TriggerEventSource</code> is one of the following values: <code>OnPostCallAnalysisAvailable</code> | <code>OnRealTimeCallAnalysisAvailable</code> | <code>OnRealTimeChatAnalysisAvailable</code> | <code>OnPostChatAnalysisAvailable</code>. Contact is categorized using the rule name.</p>
/// <p><code>RuleName</code> is used as <code>ContactCategory</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssignContactCategoryActionDefinition {}
impl AssignContactCategoryActionDefinition {
    /// Creates a new builder-style object to manufacture [`AssignContactCategoryActionDefinition`](crate::types::AssignContactCategoryActionDefinition).
    pub fn builder() -> crate::types::builders::AssignContactCategoryActionDefinitionBuilder {
        crate::types::builders::AssignContactCategoryActionDefinitionBuilder::default()
    }
}

/// A builder for [`AssignContactCategoryActionDefinition`](crate::types::AssignContactCategoryActionDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssignContactCategoryActionDefinitionBuilder {}
impl AssignContactCategoryActionDefinitionBuilder {
    /// Consumes the builder and constructs a [`AssignContactCategoryActionDefinition`](crate::types::AssignContactCategoryActionDefinition).
    pub fn build(self) -> crate::types::AssignContactCategoryActionDefinition {
        crate::types::AssignContactCategoryActionDefinition {}
    }
}
