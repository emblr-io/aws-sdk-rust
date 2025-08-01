// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates whether your instance is configured for hibernation. This parameter is valid only if the instance meets the <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html">hibernation prerequisites</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Hibernate.html">Hibernate your Amazon EC2 instance</a> in the <i>Amazon EC2 User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HibernationOptionsRequest {
    /// <p>Set to <code>true</code> to enable your instance for hibernation.</p>
    /// <p>For Spot Instances, if you set <code>Configured</code> to <code>true</code>, either omit the <code>InstanceInterruptionBehavior</code> parameter (for <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SpotMarketOptions.html"> <code>SpotMarketOptions</code> </a>), or set it to <code>hibernate</code>. When <code>Configured</code> is true:</p>
    /// <ul>
    /// <li>
    /// <p>If you omit <code>InstanceInterruptionBehavior</code>, it defaults to <code>hibernate</code>.</p></li>
    /// <li>
    /// <p>If you set <code>InstanceInterruptionBehavior</code> to a value other than <code>hibernate</code>, you'll get an error.</p></li>
    /// </ul>
    /// <p>Default: <code>false</code></p>
    pub configured: ::std::option::Option<bool>,
}
impl HibernationOptionsRequest {
    /// <p>Set to <code>true</code> to enable your instance for hibernation.</p>
    /// <p>For Spot Instances, if you set <code>Configured</code> to <code>true</code>, either omit the <code>InstanceInterruptionBehavior</code> parameter (for <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SpotMarketOptions.html"> <code>SpotMarketOptions</code> </a>), or set it to <code>hibernate</code>. When <code>Configured</code> is true:</p>
    /// <ul>
    /// <li>
    /// <p>If you omit <code>InstanceInterruptionBehavior</code>, it defaults to <code>hibernate</code>.</p></li>
    /// <li>
    /// <p>If you set <code>InstanceInterruptionBehavior</code> to a value other than <code>hibernate</code>, you'll get an error.</p></li>
    /// </ul>
    /// <p>Default: <code>false</code></p>
    pub fn configured(&self) -> ::std::option::Option<bool> {
        self.configured
    }
}
impl HibernationOptionsRequest {
    /// Creates a new builder-style object to manufacture [`HibernationOptionsRequest`](crate::types::HibernationOptionsRequest).
    pub fn builder() -> crate::types::builders::HibernationOptionsRequestBuilder {
        crate::types::builders::HibernationOptionsRequestBuilder::default()
    }
}

/// A builder for [`HibernationOptionsRequest`](crate::types::HibernationOptionsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HibernationOptionsRequestBuilder {
    pub(crate) configured: ::std::option::Option<bool>,
}
impl HibernationOptionsRequestBuilder {
    /// <p>Set to <code>true</code> to enable your instance for hibernation.</p>
    /// <p>For Spot Instances, if you set <code>Configured</code> to <code>true</code>, either omit the <code>InstanceInterruptionBehavior</code> parameter (for <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SpotMarketOptions.html"> <code>SpotMarketOptions</code> </a>), or set it to <code>hibernate</code>. When <code>Configured</code> is true:</p>
    /// <ul>
    /// <li>
    /// <p>If you omit <code>InstanceInterruptionBehavior</code>, it defaults to <code>hibernate</code>.</p></li>
    /// <li>
    /// <p>If you set <code>InstanceInterruptionBehavior</code> to a value other than <code>hibernate</code>, you'll get an error.</p></li>
    /// </ul>
    /// <p>Default: <code>false</code></p>
    pub fn configured(mut self, input: bool) -> Self {
        self.configured = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>true</code> to enable your instance for hibernation.</p>
    /// <p>For Spot Instances, if you set <code>Configured</code> to <code>true</code>, either omit the <code>InstanceInterruptionBehavior</code> parameter (for <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SpotMarketOptions.html"> <code>SpotMarketOptions</code> </a>), or set it to <code>hibernate</code>. When <code>Configured</code> is true:</p>
    /// <ul>
    /// <li>
    /// <p>If you omit <code>InstanceInterruptionBehavior</code>, it defaults to <code>hibernate</code>.</p></li>
    /// <li>
    /// <p>If you set <code>InstanceInterruptionBehavior</code> to a value other than <code>hibernate</code>, you'll get an error.</p></li>
    /// </ul>
    /// <p>Default: <code>false</code></p>
    pub fn set_configured(mut self, input: ::std::option::Option<bool>) -> Self {
        self.configured = input;
        self
    }
    /// <p>Set to <code>true</code> to enable your instance for hibernation.</p>
    /// <p>For Spot Instances, if you set <code>Configured</code> to <code>true</code>, either omit the <code>InstanceInterruptionBehavior</code> parameter (for <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SpotMarketOptions.html"> <code>SpotMarketOptions</code> </a>), or set it to <code>hibernate</code>. When <code>Configured</code> is true:</p>
    /// <ul>
    /// <li>
    /// <p>If you omit <code>InstanceInterruptionBehavior</code>, it defaults to <code>hibernate</code>.</p></li>
    /// <li>
    /// <p>If you set <code>InstanceInterruptionBehavior</code> to a value other than <code>hibernate</code>, you'll get an error.</p></li>
    /// </ul>
    /// <p>Default: <code>false</code></p>
    pub fn get_configured(&self) -> &::std::option::Option<bool> {
        &self.configured
    }
    /// Consumes the builder and constructs a [`HibernationOptionsRequest`](crate::types::HibernationOptionsRequest).
    pub fn build(self) -> crate::types::HibernationOptionsRequest {
        crate::types::HibernationOptionsRequest { configured: self.configured }
    }
}
