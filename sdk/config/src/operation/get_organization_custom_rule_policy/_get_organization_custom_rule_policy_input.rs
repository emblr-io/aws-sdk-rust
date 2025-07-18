// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOrganizationCustomRulePolicyInput {
    /// <p>The name of your organization Config Custom Policy rule.</p>
    pub organization_config_rule_name: ::std::option::Option<::std::string::String>,
}
impl GetOrganizationCustomRulePolicyInput {
    /// <p>The name of your organization Config Custom Policy rule.</p>
    pub fn organization_config_rule_name(&self) -> ::std::option::Option<&str> {
        self.organization_config_rule_name.as_deref()
    }
}
impl GetOrganizationCustomRulePolicyInput {
    /// Creates a new builder-style object to manufacture [`GetOrganizationCustomRulePolicyInput`](crate::operation::get_organization_custom_rule_policy::GetOrganizationCustomRulePolicyInput).
    pub fn builder() -> crate::operation::get_organization_custom_rule_policy::builders::GetOrganizationCustomRulePolicyInputBuilder {
        crate::operation::get_organization_custom_rule_policy::builders::GetOrganizationCustomRulePolicyInputBuilder::default()
    }
}

/// A builder for [`GetOrganizationCustomRulePolicyInput`](crate::operation::get_organization_custom_rule_policy::GetOrganizationCustomRulePolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOrganizationCustomRulePolicyInputBuilder {
    pub(crate) organization_config_rule_name: ::std::option::Option<::std::string::String>,
}
impl GetOrganizationCustomRulePolicyInputBuilder {
    /// <p>The name of your organization Config Custom Policy rule.</p>
    /// This field is required.
    pub fn organization_config_rule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_config_rule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your organization Config Custom Policy rule.</p>
    pub fn set_organization_config_rule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_config_rule_name = input;
        self
    }
    /// <p>The name of your organization Config Custom Policy rule.</p>
    pub fn get_organization_config_rule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_config_rule_name
    }
    /// Consumes the builder and constructs a [`GetOrganizationCustomRulePolicyInput`](crate::operation::get_organization_custom_rule_policy::GetOrganizationCustomRulePolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_organization_custom_rule_policy::GetOrganizationCustomRulePolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_organization_custom_rule_policy::GetOrganizationCustomRulePolicyInput {
                organization_config_rule_name: self.organization_config_rule_name,
            },
        )
    }
}
