// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of IP addresses and address ranges, in CIDR notation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleGroupVariablesIpSetsDetails {
    /// <p>The list of IP addresses and ranges.</p>
    pub definition: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupVariablesIpSetsDetails {
    /// <p>The list of IP addresses and ranges.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.definition.is_none()`.
    pub fn definition(&self) -> &[::std::string::String] {
        self.definition.as_deref().unwrap_or_default()
    }
}
impl RuleGroupVariablesIpSetsDetails {
    /// Creates a new builder-style object to manufacture [`RuleGroupVariablesIpSetsDetails`](crate::types::RuleGroupVariablesIpSetsDetails).
    pub fn builder() -> crate::types::builders::RuleGroupVariablesIpSetsDetailsBuilder {
        crate::types::builders::RuleGroupVariablesIpSetsDetailsBuilder::default()
    }
}

/// A builder for [`RuleGroupVariablesIpSetsDetails`](crate::types::RuleGroupVariablesIpSetsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleGroupVariablesIpSetsDetailsBuilder {
    pub(crate) definition: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupVariablesIpSetsDetailsBuilder {
    /// Appends an item to `definition`.
    ///
    /// To override the contents of this collection use [`set_definition`](Self::set_definition).
    ///
    /// <p>The list of IP addresses and ranges.</p>
    pub fn definition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.definition.unwrap_or_default();
        v.push(input.into());
        self.definition = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of IP addresses and ranges.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The list of IP addresses and ranges.</p>
    pub fn get_definition(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.definition
    }
    /// Consumes the builder and constructs a [`RuleGroupVariablesIpSetsDetails`](crate::types::RuleGroupVariablesIpSetsDetails).
    pub fn build(self) -> crate::types::RuleGroupVariablesIpSetsDetails {
        crate::types::RuleGroupVariablesIpSetsDetails { definition: self.definition }
    }
}
