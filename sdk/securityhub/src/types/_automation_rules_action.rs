// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>One or more actions that Security Hub takes when a finding matches the defined criteria of a rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutomationRulesAction {
    /// <p>Specifies the type of action that Security Hub takes when a finding matches the defined criteria of a rule.</p>
    pub r#type: ::std::option::Option<crate::types::AutomationRulesActionType>,
    /// <p>Specifies that the automation rule action is an update to a finding field.</p>
    pub finding_fields_update: ::std::option::Option<crate::types::AutomationRulesFindingFieldsUpdate>,
}
impl AutomationRulesAction {
    /// <p>Specifies the type of action that Security Hub takes when a finding matches the defined criteria of a rule.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::AutomationRulesActionType> {
        self.r#type.as_ref()
    }
    /// <p>Specifies that the automation rule action is an update to a finding field.</p>
    pub fn finding_fields_update(&self) -> ::std::option::Option<&crate::types::AutomationRulesFindingFieldsUpdate> {
        self.finding_fields_update.as_ref()
    }
}
impl AutomationRulesAction {
    /// Creates a new builder-style object to manufacture [`AutomationRulesAction`](crate::types::AutomationRulesAction).
    pub fn builder() -> crate::types::builders::AutomationRulesActionBuilder {
        crate::types::builders::AutomationRulesActionBuilder::default()
    }
}

/// A builder for [`AutomationRulesAction`](crate::types::AutomationRulesAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutomationRulesActionBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::AutomationRulesActionType>,
    pub(crate) finding_fields_update: ::std::option::Option<crate::types::AutomationRulesFindingFieldsUpdate>,
}
impl AutomationRulesActionBuilder {
    /// <p>Specifies the type of action that Security Hub takes when a finding matches the defined criteria of a rule.</p>
    pub fn r#type(mut self, input: crate::types::AutomationRulesActionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of action that Security Hub takes when a finding matches the defined criteria of a rule.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AutomationRulesActionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of action that Security Hub takes when a finding matches the defined criteria of a rule.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AutomationRulesActionType> {
        &self.r#type
    }
    /// <p>Specifies that the automation rule action is an update to a finding field.</p>
    pub fn finding_fields_update(mut self, input: crate::types::AutomationRulesFindingFieldsUpdate) -> Self {
        self.finding_fields_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies that the automation rule action is an update to a finding field.</p>
    pub fn set_finding_fields_update(mut self, input: ::std::option::Option<crate::types::AutomationRulesFindingFieldsUpdate>) -> Self {
        self.finding_fields_update = input;
        self
    }
    /// <p>Specifies that the automation rule action is an update to a finding field.</p>
    pub fn get_finding_fields_update(&self) -> &::std::option::Option<crate::types::AutomationRulesFindingFieldsUpdate> {
        &self.finding_fields_update
    }
    /// Consumes the builder and constructs a [`AutomationRulesAction`](crate::types::AutomationRulesAction).
    pub fn build(self) -> crate::types::AutomationRulesAction {
        crate::types::AutomationRulesAction {
            r#type: self.r#type,
            finding_fields_update: self.finding_fields_update,
        }
    }
}
