// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration details for a lifecycle policy resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecyclePolicyDetail {
    /// <p>Configuration details for the policy action.</p>
    pub action: ::std::option::Option<crate::types::LifecyclePolicyDetailAction>,
    /// <p>Specifies the resources that the lifecycle policy applies to.</p>
    pub filter: ::std::option::Option<crate::types::LifecyclePolicyDetailFilter>,
    /// <p>Additional rules to specify resources that should be exempt from policy actions.</p>
    pub exclusion_rules: ::std::option::Option<crate::types::LifecyclePolicyDetailExclusionRules>,
}
impl LifecyclePolicyDetail {
    /// <p>Configuration details for the policy action.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::LifecyclePolicyDetailAction> {
        self.action.as_ref()
    }
    /// <p>Specifies the resources that the lifecycle policy applies to.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::LifecyclePolicyDetailFilter> {
        self.filter.as_ref()
    }
    /// <p>Additional rules to specify resources that should be exempt from policy actions.</p>
    pub fn exclusion_rules(&self) -> ::std::option::Option<&crate::types::LifecyclePolicyDetailExclusionRules> {
        self.exclusion_rules.as_ref()
    }
}
impl LifecyclePolicyDetail {
    /// Creates a new builder-style object to manufacture [`LifecyclePolicyDetail`](crate::types::LifecyclePolicyDetail).
    pub fn builder() -> crate::types::builders::LifecyclePolicyDetailBuilder {
        crate::types::builders::LifecyclePolicyDetailBuilder::default()
    }
}

/// A builder for [`LifecyclePolicyDetail`](crate::types::LifecyclePolicyDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecyclePolicyDetailBuilder {
    pub(crate) action: ::std::option::Option<crate::types::LifecyclePolicyDetailAction>,
    pub(crate) filter: ::std::option::Option<crate::types::LifecyclePolicyDetailFilter>,
    pub(crate) exclusion_rules: ::std::option::Option<crate::types::LifecyclePolicyDetailExclusionRules>,
}
impl LifecyclePolicyDetailBuilder {
    /// <p>Configuration details for the policy action.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::LifecyclePolicyDetailAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration details for the policy action.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::LifecyclePolicyDetailAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Configuration details for the policy action.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::LifecyclePolicyDetailAction> {
        &self.action
    }
    /// <p>Specifies the resources that the lifecycle policy applies to.</p>
    /// This field is required.
    pub fn filter(mut self, input: crate::types::LifecyclePolicyDetailFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the resources that the lifecycle policy applies to.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::LifecyclePolicyDetailFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>Specifies the resources that the lifecycle policy applies to.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::LifecyclePolicyDetailFilter> {
        &self.filter
    }
    /// <p>Additional rules to specify resources that should be exempt from policy actions.</p>
    pub fn exclusion_rules(mut self, input: crate::types::LifecyclePolicyDetailExclusionRules) -> Self {
        self.exclusion_rules = ::std::option::Option::Some(input);
        self
    }
    /// <p>Additional rules to specify resources that should be exempt from policy actions.</p>
    pub fn set_exclusion_rules(mut self, input: ::std::option::Option<crate::types::LifecyclePolicyDetailExclusionRules>) -> Self {
        self.exclusion_rules = input;
        self
    }
    /// <p>Additional rules to specify resources that should be exempt from policy actions.</p>
    pub fn get_exclusion_rules(&self) -> &::std::option::Option<crate::types::LifecyclePolicyDetailExclusionRules> {
        &self.exclusion_rules
    }
    /// Consumes the builder and constructs a [`LifecyclePolicyDetail`](crate::types::LifecyclePolicyDetail).
    pub fn build(self) -> crate::types::LifecyclePolicyDetail {
        crate::types::LifecyclePolicyDetail {
            action: self.action,
            filter: self.filter,
            exclusion_rules: self.exclusion_rules,
        }
    }
}
