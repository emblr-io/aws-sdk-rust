// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A set of TCP flags and masks to inspect for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleGroupSourceStatelessRuleMatchAttributesTcpFlags {
    /// <p>Defines the flags from the <code>Masks</code> setting that must be set in order for the packet to match. Flags that are listed must be set. Flags that are not listed must not be set.</p>
    pub flags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The set of flags to consider in the inspection. If not specified, then all flags are inspected.</p>
    pub masks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupSourceStatelessRuleMatchAttributesTcpFlags {
    /// <p>Defines the flags from the <code>Masks</code> setting that must be set in order for the packet to match. Flags that are listed must be set. Flags that are not listed must not be set.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.flags.is_none()`.
    pub fn flags(&self) -> &[::std::string::String] {
        self.flags.as_deref().unwrap_or_default()
    }
    /// <p>The set of flags to consider in the inspection. If not specified, then all flags are inspected.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.masks.is_none()`.
    pub fn masks(&self) -> &[::std::string::String] {
        self.masks.as_deref().unwrap_or_default()
    }
}
impl RuleGroupSourceStatelessRuleMatchAttributesTcpFlags {
    /// Creates a new builder-style object to manufacture [`RuleGroupSourceStatelessRuleMatchAttributesTcpFlags`](crate::types::RuleGroupSourceStatelessRuleMatchAttributesTcpFlags).
    pub fn builder() -> crate::types::builders::RuleGroupSourceStatelessRuleMatchAttributesTcpFlagsBuilder {
        crate::types::builders::RuleGroupSourceStatelessRuleMatchAttributesTcpFlagsBuilder::default()
    }
}

/// A builder for [`RuleGroupSourceStatelessRuleMatchAttributesTcpFlags`](crate::types::RuleGroupSourceStatelessRuleMatchAttributesTcpFlags).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleGroupSourceStatelessRuleMatchAttributesTcpFlagsBuilder {
    pub(crate) flags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) masks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupSourceStatelessRuleMatchAttributesTcpFlagsBuilder {
    /// Appends an item to `flags`.
    ///
    /// To override the contents of this collection use [`set_flags`](Self::set_flags).
    ///
    /// <p>Defines the flags from the <code>Masks</code> setting that must be set in order for the packet to match. Flags that are listed must be set. Flags that are not listed must not be set.</p>
    pub fn flags(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.flags.unwrap_or_default();
        v.push(input.into());
        self.flags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines the flags from the <code>Masks</code> setting that must be set in order for the packet to match. Flags that are listed must be set. Flags that are not listed must not be set.</p>
    pub fn set_flags(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.flags = input;
        self
    }
    /// <p>Defines the flags from the <code>Masks</code> setting that must be set in order for the packet to match. Flags that are listed must be set. Flags that are not listed must not be set.</p>
    pub fn get_flags(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.flags
    }
    /// Appends an item to `masks`.
    ///
    /// To override the contents of this collection use [`set_masks`](Self::set_masks).
    ///
    /// <p>The set of flags to consider in the inspection. If not specified, then all flags are inspected.</p>
    pub fn masks(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.masks.unwrap_or_default();
        v.push(input.into());
        self.masks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The set of flags to consider in the inspection. If not specified, then all flags are inspected.</p>
    pub fn set_masks(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.masks = input;
        self
    }
    /// <p>The set of flags to consider in the inspection. If not specified, then all flags are inspected.</p>
    pub fn get_masks(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.masks
    }
    /// Consumes the builder and constructs a [`RuleGroupSourceStatelessRuleMatchAttributesTcpFlags`](crate::types::RuleGroupSourceStatelessRuleMatchAttributesTcpFlags).
    pub fn build(self) -> crate::types::RuleGroupSourceStatelessRuleMatchAttributesTcpFlags {
        crate::types::RuleGroupSourceStatelessRuleMatchAttributesTcpFlags {
            flags: self.flags,
            masks: self.masks,
        }
    }
}
