// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies how WAF should handle <code>CAPTCHA</code> evaluations. This is available at the web ACL level and in each rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CaptchaConfig {
    /// <p>Determines how long a <code>CAPTCHA</code> timestamp in the token remains valid after the client successfully solves a <code>CAPTCHA</code> puzzle.</p>
    pub immunity_time_property: ::std::option::Option<crate::types::ImmunityTimeProperty>,
}
impl CaptchaConfig {
    /// <p>Determines how long a <code>CAPTCHA</code> timestamp in the token remains valid after the client successfully solves a <code>CAPTCHA</code> puzzle.</p>
    pub fn immunity_time_property(&self) -> ::std::option::Option<&crate::types::ImmunityTimeProperty> {
        self.immunity_time_property.as_ref()
    }
}
impl CaptchaConfig {
    /// Creates a new builder-style object to manufacture [`CaptchaConfig`](crate::types::CaptchaConfig).
    pub fn builder() -> crate::types::builders::CaptchaConfigBuilder {
        crate::types::builders::CaptchaConfigBuilder::default()
    }
}

/// A builder for [`CaptchaConfig`](crate::types::CaptchaConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CaptchaConfigBuilder {
    pub(crate) immunity_time_property: ::std::option::Option<crate::types::ImmunityTimeProperty>,
}
impl CaptchaConfigBuilder {
    /// <p>Determines how long a <code>CAPTCHA</code> timestamp in the token remains valid after the client successfully solves a <code>CAPTCHA</code> puzzle.</p>
    pub fn immunity_time_property(mut self, input: crate::types::ImmunityTimeProperty) -> Self {
        self.immunity_time_property = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines how long a <code>CAPTCHA</code> timestamp in the token remains valid after the client successfully solves a <code>CAPTCHA</code> puzzle.</p>
    pub fn set_immunity_time_property(mut self, input: ::std::option::Option<crate::types::ImmunityTimeProperty>) -> Self {
        self.immunity_time_property = input;
        self
    }
    /// <p>Determines how long a <code>CAPTCHA</code> timestamp in the token remains valid after the client successfully solves a <code>CAPTCHA</code> puzzle.</p>
    pub fn get_immunity_time_property(&self) -> &::std::option::Option<crate::types::ImmunityTimeProperty> {
        &self.immunity_time_property
    }
    /// Consumes the builder and constructs a [`CaptchaConfig`](crate::types::CaptchaConfig).
    pub fn build(self) -> crate::types::CaptchaConfig {
        crate::types::CaptchaConfig {
            immunity_time_property: self.immunity_time_property,
        }
    }
}
