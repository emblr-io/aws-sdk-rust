// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFirewallRuleOutput {
    /// <p>The firewall rule that you just created.</p>
    pub firewall_rule: ::std::option::Option<crate::types::FirewallRule>,
    _request_id: Option<String>,
}
impl CreateFirewallRuleOutput {
    /// <p>The firewall rule that you just created.</p>
    pub fn firewall_rule(&self) -> ::std::option::Option<&crate::types::FirewallRule> {
        self.firewall_rule.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateFirewallRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateFirewallRuleOutput {
    /// Creates a new builder-style object to manufacture [`CreateFirewallRuleOutput`](crate::operation::create_firewall_rule::CreateFirewallRuleOutput).
    pub fn builder() -> crate::operation::create_firewall_rule::builders::CreateFirewallRuleOutputBuilder {
        crate::operation::create_firewall_rule::builders::CreateFirewallRuleOutputBuilder::default()
    }
}

/// A builder for [`CreateFirewallRuleOutput`](crate::operation::create_firewall_rule::CreateFirewallRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFirewallRuleOutputBuilder {
    pub(crate) firewall_rule: ::std::option::Option<crate::types::FirewallRule>,
    _request_id: Option<String>,
}
impl CreateFirewallRuleOutputBuilder {
    /// <p>The firewall rule that you just created.</p>
    pub fn firewall_rule(mut self, input: crate::types::FirewallRule) -> Self {
        self.firewall_rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The firewall rule that you just created.</p>
    pub fn set_firewall_rule(mut self, input: ::std::option::Option<crate::types::FirewallRule>) -> Self {
        self.firewall_rule = input;
        self
    }
    /// <p>The firewall rule that you just created.</p>
    pub fn get_firewall_rule(&self) -> &::std::option::Option<crate::types::FirewallRule> {
        &self.firewall_rule
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateFirewallRuleOutput`](crate::operation::create_firewall_rule::CreateFirewallRuleOutput).
    pub fn build(self) -> crate::operation::create_firewall_rule::CreateFirewallRuleOutput {
        crate::operation::create_firewall_rule::CreateFirewallRuleOutput {
            firewall_rule: self.firewall_rule,
            _request_id: self._request_id,
        }
    }
}
