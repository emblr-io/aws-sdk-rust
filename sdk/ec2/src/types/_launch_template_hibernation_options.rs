// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates whether an instance is configured for hibernation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateHibernationOptions {
    /// <p>If this parameter is set to <code>true</code>, the instance is enabled for hibernation; otherwise, it is not enabled for hibernation.</p>
    pub configured: ::std::option::Option<bool>,
}
impl LaunchTemplateHibernationOptions {
    /// <p>If this parameter is set to <code>true</code>, the instance is enabled for hibernation; otherwise, it is not enabled for hibernation.</p>
    pub fn configured(&self) -> ::std::option::Option<bool> {
        self.configured
    }
}
impl LaunchTemplateHibernationOptions {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateHibernationOptions`](crate::types::LaunchTemplateHibernationOptions).
    pub fn builder() -> crate::types::builders::LaunchTemplateHibernationOptionsBuilder {
        crate::types::builders::LaunchTemplateHibernationOptionsBuilder::default()
    }
}

/// A builder for [`LaunchTemplateHibernationOptions`](crate::types::LaunchTemplateHibernationOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateHibernationOptionsBuilder {
    pub(crate) configured: ::std::option::Option<bool>,
}
impl LaunchTemplateHibernationOptionsBuilder {
    /// <p>If this parameter is set to <code>true</code>, the instance is enabled for hibernation; otherwise, it is not enabled for hibernation.</p>
    pub fn configured(mut self, input: bool) -> Self {
        self.configured = ::std::option::Option::Some(input);
        self
    }
    /// <p>If this parameter is set to <code>true</code>, the instance is enabled for hibernation; otherwise, it is not enabled for hibernation.</p>
    pub fn set_configured(mut self, input: ::std::option::Option<bool>) -> Self {
        self.configured = input;
        self
    }
    /// <p>If this parameter is set to <code>true</code>, the instance is enabled for hibernation; otherwise, it is not enabled for hibernation.</p>
    pub fn get_configured(&self) -> &::std::option::Option<bool> {
        &self.configured
    }
    /// Consumes the builder and constructs a [`LaunchTemplateHibernationOptions`](crate::types::LaunchTemplateHibernationOptions).
    pub fn build(self) -> crate::types::LaunchTemplateHibernationOptions {
        crate::types::LaunchTemplateHibernationOptions { configured: self.configured }
    }
}
