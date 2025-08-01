// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A rule option for a stateful rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleGroupSourceStatefulRulesOptionsDetails {
    /// <p>A keyword to look for.</p>
    pub keyword: ::std::option::Option<::std::string::String>,
    /// <p>A list of settings.</p>
    pub settings: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupSourceStatefulRulesOptionsDetails {
    /// <p>A keyword to look for.</p>
    pub fn keyword(&self) -> ::std::option::Option<&str> {
        self.keyword.as_deref()
    }
    /// <p>A list of settings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.settings.is_none()`.
    pub fn settings(&self) -> &[::std::string::String] {
        self.settings.as_deref().unwrap_or_default()
    }
}
impl RuleGroupSourceStatefulRulesOptionsDetails {
    /// Creates a new builder-style object to manufacture [`RuleGroupSourceStatefulRulesOptionsDetails`](crate::types::RuleGroupSourceStatefulRulesOptionsDetails).
    pub fn builder() -> crate::types::builders::RuleGroupSourceStatefulRulesOptionsDetailsBuilder {
        crate::types::builders::RuleGroupSourceStatefulRulesOptionsDetailsBuilder::default()
    }
}

/// A builder for [`RuleGroupSourceStatefulRulesOptionsDetails`](crate::types::RuleGroupSourceStatefulRulesOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleGroupSourceStatefulRulesOptionsDetailsBuilder {
    pub(crate) keyword: ::std::option::Option<::std::string::String>,
    pub(crate) settings: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RuleGroupSourceStatefulRulesOptionsDetailsBuilder {
    /// <p>A keyword to look for.</p>
    pub fn keyword(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyword = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A keyword to look for.</p>
    pub fn set_keyword(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyword = input;
        self
    }
    /// <p>A keyword to look for.</p>
    pub fn get_keyword(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyword
    }
    /// Appends an item to `settings`.
    ///
    /// To override the contents of this collection use [`set_settings`](Self::set_settings).
    ///
    /// <p>A list of settings.</p>
    pub fn settings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.settings.unwrap_or_default();
        v.push(input.into());
        self.settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of settings.</p>
    pub fn set_settings(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.settings = input;
        self
    }
    /// <p>A list of settings.</p>
    pub fn get_settings(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.settings
    }
    /// Consumes the builder and constructs a [`RuleGroupSourceStatefulRulesOptionsDetails`](crate::types::RuleGroupSourceStatefulRulesOptionsDetails).
    pub fn build(self) -> crate::types::RuleGroupSourceStatefulRulesOptionsDetails {
        crate::types::RuleGroupSourceStatefulRulesOptionsDetails {
            keyword: self.keyword,
            settings: self.settings,
        }
    }
}
