// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFirewallRuleGroupAssociationOutput {
    /// <p>The association that you requested.</p>
    pub firewall_rule_group_association: ::std::option::Option<crate::types::FirewallRuleGroupAssociation>,
    _request_id: Option<String>,
}
impl GetFirewallRuleGroupAssociationOutput {
    /// <p>The association that you requested.</p>
    pub fn firewall_rule_group_association(&self) -> ::std::option::Option<&crate::types::FirewallRuleGroupAssociation> {
        self.firewall_rule_group_association.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetFirewallRuleGroupAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFirewallRuleGroupAssociationOutput {
    /// Creates a new builder-style object to manufacture [`GetFirewallRuleGroupAssociationOutput`](crate::operation::get_firewall_rule_group_association::GetFirewallRuleGroupAssociationOutput).
    pub fn builder() -> crate::operation::get_firewall_rule_group_association::builders::GetFirewallRuleGroupAssociationOutputBuilder {
        crate::operation::get_firewall_rule_group_association::builders::GetFirewallRuleGroupAssociationOutputBuilder::default()
    }
}

/// A builder for [`GetFirewallRuleGroupAssociationOutput`](crate::operation::get_firewall_rule_group_association::GetFirewallRuleGroupAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFirewallRuleGroupAssociationOutputBuilder {
    pub(crate) firewall_rule_group_association: ::std::option::Option<crate::types::FirewallRuleGroupAssociation>,
    _request_id: Option<String>,
}
impl GetFirewallRuleGroupAssociationOutputBuilder {
    /// <p>The association that you requested.</p>
    pub fn firewall_rule_group_association(mut self, input: crate::types::FirewallRuleGroupAssociation) -> Self {
        self.firewall_rule_group_association = ::std::option::Option::Some(input);
        self
    }
    /// <p>The association that you requested.</p>
    pub fn set_firewall_rule_group_association(mut self, input: ::std::option::Option<crate::types::FirewallRuleGroupAssociation>) -> Self {
        self.firewall_rule_group_association = input;
        self
    }
    /// <p>The association that you requested.</p>
    pub fn get_firewall_rule_group_association(&self) -> &::std::option::Option<crate::types::FirewallRuleGroupAssociation> {
        &self.firewall_rule_group_association
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFirewallRuleGroupAssociationOutput`](crate::operation::get_firewall_rule_group_association::GetFirewallRuleGroupAssociationOutput).
    pub fn build(self) -> crate::operation::get_firewall_rule_group_association::GetFirewallRuleGroupAssociationOutput {
        crate::operation::get_firewall_rule_group_association::GetFirewallRuleGroupAssociationOutput {
            firewall_rule_group_association: self.firewall_rule_group_association,
            _request_id: self._request_id,
        }
    }
}
