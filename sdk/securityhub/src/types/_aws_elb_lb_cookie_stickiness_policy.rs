// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a stickiness policy that was created using <code>CreateLBCookieStickinessPolicy</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsElbLbCookieStickinessPolicy {
    /// <p>The amount of time, in seconds, after which the cookie is considered stale. If an expiration period is not specified, the stickiness session lasts for the duration of the browser session.</p>
    pub cookie_expiration_period: ::std::option::Option<i64>,
    /// <p>The name of the policy. The name must be unique within the set of policies for the load balancer.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
}
impl AwsElbLbCookieStickinessPolicy {
    /// <p>The amount of time, in seconds, after which the cookie is considered stale. If an expiration period is not specified, the stickiness session lasts for the duration of the browser session.</p>
    pub fn cookie_expiration_period(&self) -> ::std::option::Option<i64> {
        self.cookie_expiration_period
    }
    /// <p>The name of the policy. The name must be unique within the set of policies for the load balancer.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
}
impl AwsElbLbCookieStickinessPolicy {
    /// Creates a new builder-style object to manufacture [`AwsElbLbCookieStickinessPolicy`](crate::types::AwsElbLbCookieStickinessPolicy).
    pub fn builder() -> crate::types::builders::AwsElbLbCookieStickinessPolicyBuilder {
        crate::types::builders::AwsElbLbCookieStickinessPolicyBuilder::default()
    }
}

/// A builder for [`AwsElbLbCookieStickinessPolicy`](crate::types::AwsElbLbCookieStickinessPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsElbLbCookieStickinessPolicyBuilder {
    pub(crate) cookie_expiration_period: ::std::option::Option<i64>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
}
impl AwsElbLbCookieStickinessPolicyBuilder {
    /// <p>The amount of time, in seconds, after which the cookie is considered stale. If an expiration period is not specified, the stickiness session lasts for the duration of the browser session.</p>
    pub fn cookie_expiration_period(mut self, input: i64) -> Self {
        self.cookie_expiration_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time, in seconds, after which the cookie is considered stale. If an expiration period is not specified, the stickiness session lasts for the duration of the browser session.</p>
    pub fn set_cookie_expiration_period(mut self, input: ::std::option::Option<i64>) -> Self {
        self.cookie_expiration_period = input;
        self
    }
    /// <p>The amount of time, in seconds, after which the cookie is considered stale. If an expiration period is not specified, the stickiness session lasts for the duration of the browser session.</p>
    pub fn get_cookie_expiration_period(&self) -> &::std::option::Option<i64> {
        &self.cookie_expiration_period
    }
    /// <p>The name of the policy. The name must be unique within the set of policies for the load balancer.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the policy. The name must be unique within the set of policies for the load balancer.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the policy. The name must be unique within the set of policies for the load balancer.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// Consumes the builder and constructs a [`AwsElbLbCookieStickinessPolicy`](crate::types::AwsElbLbCookieStickinessPolicy).
    pub fn build(self) -> crate::types::AwsElbLbCookieStickinessPolicy {
        crate::types::AwsElbLbCookieStickinessPolicy {
            cookie_expiration_period: self.cookie_expiration_period,
            policy_name: self.policy_name,
        }
    }
}
