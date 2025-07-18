// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the policies for a load balancer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsElbLoadBalancerPolicies {
    /// <p>The stickiness policies that are created using <code>CreateAppCookieStickinessPolicy</code>.</p>
    pub app_cookie_stickiness_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbAppCookieStickinessPolicy>>,
    /// <p>The stickiness policies that are created using <code>CreateLBCookieStickinessPolicy</code>.</p>
    pub lb_cookie_stickiness_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbLbCookieStickinessPolicy>>,
    /// <p>The policies other than the stickiness policies.</p>
    pub other_policies: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AwsElbLoadBalancerPolicies {
    /// <p>The stickiness policies that are created using <code>CreateAppCookieStickinessPolicy</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.app_cookie_stickiness_policies.is_none()`.
    pub fn app_cookie_stickiness_policies(&self) -> &[crate::types::AwsElbAppCookieStickinessPolicy] {
        self.app_cookie_stickiness_policies.as_deref().unwrap_or_default()
    }
    /// <p>The stickiness policies that are created using <code>CreateLBCookieStickinessPolicy</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lb_cookie_stickiness_policies.is_none()`.
    pub fn lb_cookie_stickiness_policies(&self) -> &[crate::types::AwsElbLbCookieStickinessPolicy] {
        self.lb_cookie_stickiness_policies.as_deref().unwrap_or_default()
    }
    /// <p>The policies other than the stickiness policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.other_policies.is_none()`.
    pub fn other_policies(&self) -> &[::std::string::String] {
        self.other_policies.as_deref().unwrap_or_default()
    }
}
impl AwsElbLoadBalancerPolicies {
    /// Creates a new builder-style object to manufacture [`AwsElbLoadBalancerPolicies`](crate::types::AwsElbLoadBalancerPolicies).
    pub fn builder() -> crate::types::builders::AwsElbLoadBalancerPoliciesBuilder {
        crate::types::builders::AwsElbLoadBalancerPoliciesBuilder::default()
    }
}

/// A builder for [`AwsElbLoadBalancerPolicies`](crate::types::AwsElbLoadBalancerPolicies).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsElbLoadBalancerPoliciesBuilder {
    pub(crate) app_cookie_stickiness_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbAppCookieStickinessPolicy>>,
    pub(crate) lb_cookie_stickiness_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbLbCookieStickinessPolicy>>,
    pub(crate) other_policies: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AwsElbLoadBalancerPoliciesBuilder {
    /// Appends an item to `app_cookie_stickiness_policies`.
    ///
    /// To override the contents of this collection use [`set_app_cookie_stickiness_policies`](Self::set_app_cookie_stickiness_policies).
    ///
    /// <p>The stickiness policies that are created using <code>CreateAppCookieStickinessPolicy</code>.</p>
    pub fn app_cookie_stickiness_policies(mut self, input: crate::types::AwsElbAppCookieStickinessPolicy) -> Self {
        let mut v = self.app_cookie_stickiness_policies.unwrap_or_default();
        v.push(input);
        self.app_cookie_stickiness_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The stickiness policies that are created using <code>CreateAppCookieStickinessPolicy</code>.</p>
    pub fn set_app_cookie_stickiness_policies(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbAppCookieStickinessPolicy>>,
    ) -> Self {
        self.app_cookie_stickiness_policies = input;
        self
    }
    /// <p>The stickiness policies that are created using <code>CreateAppCookieStickinessPolicy</code>.</p>
    pub fn get_app_cookie_stickiness_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsElbAppCookieStickinessPolicy>> {
        &self.app_cookie_stickiness_policies
    }
    /// Appends an item to `lb_cookie_stickiness_policies`.
    ///
    /// To override the contents of this collection use [`set_lb_cookie_stickiness_policies`](Self::set_lb_cookie_stickiness_policies).
    ///
    /// <p>The stickiness policies that are created using <code>CreateLBCookieStickinessPolicy</code>.</p>
    pub fn lb_cookie_stickiness_policies(mut self, input: crate::types::AwsElbLbCookieStickinessPolicy) -> Self {
        let mut v = self.lb_cookie_stickiness_policies.unwrap_or_default();
        v.push(input);
        self.lb_cookie_stickiness_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The stickiness policies that are created using <code>CreateLBCookieStickinessPolicy</code>.</p>
    pub fn set_lb_cookie_stickiness_policies(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AwsElbLbCookieStickinessPolicy>>,
    ) -> Self {
        self.lb_cookie_stickiness_policies = input;
        self
    }
    /// <p>The stickiness policies that are created using <code>CreateLBCookieStickinessPolicy</code>.</p>
    pub fn get_lb_cookie_stickiness_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsElbLbCookieStickinessPolicy>> {
        &self.lb_cookie_stickiness_policies
    }
    /// Appends an item to `other_policies`.
    ///
    /// To override the contents of this collection use [`set_other_policies`](Self::set_other_policies).
    ///
    /// <p>The policies other than the stickiness policies.</p>
    pub fn other_policies(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.other_policies.unwrap_or_default();
        v.push(input.into());
        self.other_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The policies other than the stickiness policies.</p>
    pub fn set_other_policies(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.other_policies = input;
        self
    }
    /// <p>The policies other than the stickiness policies.</p>
    pub fn get_other_policies(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.other_policies
    }
    /// Consumes the builder and constructs a [`AwsElbLoadBalancerPolicies`](crate::types::AwsElbLoadBalancerPolicies).
    pub fn build(self) -> crate::types::AwsElbLoadBalancerPolicies {
        crate::types::AwsElbLoadBalancerPolicies {
            app_cookie_stickiness_policies: self.app_cookie_stickiness_policies,
            lb_cookie_stickiness_policies: self.lb_cookie_stickiness_policies,
            other_policies: self.other_policies,
        }
    }
}
