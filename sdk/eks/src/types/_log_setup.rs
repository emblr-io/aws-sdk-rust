// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the enabled or disabled Kubernetes control plane logs for your cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogSetup {
    /// <p>The available cluster control plane log types.</p>
    pub types: ::std::option::Option<::std::vec::Vec<crate::types::LogType>>,
    /// <p>If a log type is enabled, that log type exports its control plane logs to CloudWatch Logs . If a log type isn't enabled, that log type doesn't export its control plane logs. Each individual log type can be enabled or disabled independently.</p>
    pub enabled: ::std::option::Option<bool>,
}
impl LogSetup {
    /// <p>The available cluster control plane log types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.types.is_none()`.
    pub fn types(&self) -> &[crate::types::LogType] {
        self.types.as_deref().unwrap_or_default()
    }
    /// <p>If a log type is enabled, that log type exports its control plane logs to CloudWatch Logs . If a log type isn't enabled, that log type doesn't export its control plane logs. Each individual log type can be enabled or disabled independently.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl LogSetup {
    /// Creates a new builder-style object to manufacture [`LogSetup`](crate::types::LogSetup).
    pub fn builder() -> crate::types::builders::LogSetupBuilder {
        crate::types::builders::LogSetupBuilder::default()
    }
}

/// A builder for [`LogSetup`](crate::types::LogSetup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogSetupBuilder {
    pub(crate) types: ::std::option::Option<::std::vec::Vec<crate::types::LogType>>,
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl LogSetupBuilder {
    /// Appends an item to `types`.
    ///
    /// To override the contents of this collection use [`set_types`](Self::set_types).
    ///
    /// <p>The available cluster control plane log types.</p>
    pub fn types(mut self, input: crate::types::LogType) -> Self {
        let mut v = self.types.unwrap_or_default();
        v.push(input);
        self.types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The available cluster control plane log types.</p>
    pub fn set_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LogType>>) -> Self {
        self.types = input;
        self
    }
    /// <p>The available cluster control plane log types.</p>
    pub fn get_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LogType>> {
        &self.types
    }
    /// <p>If a log type is enabled, that log type exports its control plane logs to CloudWatch Logs . If a log type isn't enabled, that log type doesn't export its control plane logs. Each individual log type can be enabled or disabled independently.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>If a log type is enabled, that log type exports its control plane logs to CloudWatch Logs . If a log type isn't enabled, that log type doesn't export its control plane logs. Each individual log type can be enabled or disabled independently.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>If a log type is enabled, that log type exports its control plane logs to CloudWatch Logs . If a log type isn't enabled, that log type doesn't export its control plane logs. Each individual log type can be enabled or disabled independently.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`LogSetup`](crate::types::LogSetup).
    pub fn build(self) -> crate::types::LogSetup {
        crate::types::LogSetup {
            types: self.types,
            enabled: self.enabled,
        }
    }
}
