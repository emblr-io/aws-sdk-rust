// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates whether the instance is configured for hibernation. This parameter is valid only if the instance meets the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html">hibernation prerequisites</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateHibernationOptionsRequest {
    /// <p>If you set this parameter to <code>true</code>, the instance is enabled for hibernation.</p>
    /// <p>Default: <code>false</code></p>
    pub configured: ::std::option::Option<bool>,
}
impl LaunchTemplateHibernationOptionsRequest {
    /// <p>If you set this parameter to <code>true</code>, the instance is enabled for hibernation.</p>
    /// <p>Default: <code>false</code></p>
    pub fn configured(&self) -> ::std::option::Option<bool> {
        self.configured
    }
}
impl LaunchTemplateHibernationOptionsRequest {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateHibernationOptionsRequest`](crate::types::LaunchTemplateHibernationOptionsRequest).
    pub fn builder() -> crate::types::builders::LaunchTemplateHibernationOptionsRequestBuilder {
        crate::types::builders::LaunchTemplateHibernationOptionsRequestBuilder::default()
    }
}

/// A builder for [`LaunchTemplateHibernationOptionsRequest`](crate::types::LaunchTemplateHibernationOptionsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateHibernationOptionsRequestBuilder {
    pub(crate) configured: ::std::option::Option<bool>,
}
impl LaunchTemplateHibernationOptionsRequestBuilder {
    /// <p>If you set this parameter to <code>true</code>, the instance is enabled for hibernation.</p>
    /// <p>Default: <code>false</code></p>
    pub fn configured(mut self, input: bool) -> Self {
        self.configured = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you set this parameter to <code>true</code>, the instance is enabled for hibernation.</p>
    /// <p>Default: <code>false</code></p>
    pub fn set_configured(mut self, input: ::std::option::Option<bool>) -> Self {
        self.configured = input;
        self
    }
    /// <p>If you set this parameter to <code>true</code>, the instance is enabled for hibernation.</p>
    /// <p>Default: <code>false</code></p>
    pub fn get_configured(&self) -> &::std::option::Option<bool> {
        &self.configured
    }
    /// Consumes the builder and constructs a [`LaunchTemplateHibernationOptionsRequest`](crate::types::LaunchTemplateHibernationOptionsRequest).
    pub fn build(self) -> crate::types::LaunchTemplateHibernationOptionsRequest {
        crate::types::LaunchTemplateHibernationOptionsRequest { configured: self.configured }
    }
}
