// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the configuration settings for real-time alerts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RealTimeAlertConfiguration {
    /// <p>Turns off real-time alerts.</p>
    pub disabled: bool,
    /// <p>The rules in the alert. Rules specify the words or phrases that you want to be notified about.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::RealTimeAlertRule>>,
}
impl RealTimeAlertConfiguration {
    /// <p>Turns off real-time alerts.</p>
    pub fn disabled(&self) -> bool {
        self.disabled
    }
    /// <p>The rules in the alert. Rules specify the words or phrases that you want to be notified about.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::RealTimeAlertRule] {
        self.rules.as_deref().unwrap_or_default()
    }
}
impl RealTimeAlertConfiguration {
    /// Creates a new builder-style object to manufacture [`RealTimeAlertConfiguration`](crate::types::RealTimeAlertConfiguration).
    pub fn builder() -> crate::types::builders::RealTimeAlertConfigurationBuilder {
        crate::types::builders::RealTimeAlertConfigurationBuilder::default()
    }
}

/// A builder for [`RealTimeAlertConfiguration`](crate::types::RealTimeAlertConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RealTimeAlertConfigurationBuilder {
    pub(crate) disabled: ::std::option::Option<bool>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::RealTimeAlertRule>>,
}
impl RealTimeAlertConfigurationBuilder {
    /// <p>Turns off real-time alerts.</p>
    pub fn disabled(mut self, input: bool) -> Self {
        self.disabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Turns off real-time alerts.</p>
    pub fn set_disabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disabled = input;
        self
    }
    /// <p>Turns off real-time alerts.</p>
    pub fn get_disabled(&self) -> &::std::option::Option<bool> {
        &self.disabled
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>The rules in the alert. Rules specify the words or phrases that you want to be notified about.</p>
    pub fn rules(mut self, input: crate::types::RealTimeAlertRule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The rules in the alert. Rules specify the words or phrases that you want to be notified about.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RealTimeAlertRule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>The rules in the alert. Rules specify the words or phrases that you want to be notified about.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RealTimeAlertRule>> {
        &self.rules
    }
    /// Consumes the builder and constructs a [`RealTimeAlertConfiguration`](crate::types::RealTimeAlertConfiguration).
    pub fn build(self) -> crate::types::RealTimeAlertConfiguration {
        crate::types::RealTimeAlertConfiguration {
            disabled: self.disabled.unwrap_or_default(),
            rules: self.rules,
        }
    }
}
