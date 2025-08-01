// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartConfigurationPolicyDisassociationInput {
    /// <p>The identifier of the target account, organizational unit, or the root to disassociate from the specified configuration.</p>
    pub target: ::std::option::Option<crate::types::Target>,
    /// <p>The Amazon Resource Name (ARN) of a configuration policy, the universally unique identifier (UUID) of a configuration policy, or a value of <code>SELF_MANAGED_SECURITY_HUB</code> for a self-managed configuration.</p>
    pub configuration_policy_identifier: ::std::option::Option<::std::string::String>,
}
impl StartConfigurationPolicyDisassociationInput {
    /// <p>The identifier of the target account, organizational unit, or the root to disassociate from the specified configuration.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::Target> {
        self.target.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of a configuration policy, the universally unique identifier (UUID) of a configuration policy, or a value of <code>SELF_MANAGED_SECURITY_HUB</code> for a self-managed configuration.</p>
    pub fn configuration_policy_identifier(&self) -> ::std::option::Option<&str> {
        self.configuration_policy_identifier.as_deref()
    }
}
impl StartConfigurationPolicyDisassociationInput {
    /// Creates a new builder-style object to manufacture [`StartConfigurationPolicyDisassociationInput`](crate::operation::start_configuration_policy_disassociation::StartConfigurationPolicyDisassociationInput).
    pub fn builder() -> crate::operation::start_configuration_policy_disassociation::builders::StartConfigurationPolicyDisassociationInputBuilder {
        crate::operation::start_configuration_policy_disassociation::builders::StartConfigurationPolicyDisassociationInputBuilder::default()
    }
}

/// A builder for [`StartConfigurationPolicyDisassociationInput`](crate::operation::start_configuration_policy_disassociation::StartConfigurationPolicyDisassociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartConfigurationPolicyDisassociationInputBuilder {
    pub(crate) target: ::std::option::Option<crate::types::Target>,
    pub(crate) configuration_policy_identifier: ::std::option::Option<::std::string::String>,
}
impl StartConfigurationPolicyDisassociationInputBuilder {
    /// <p>The identifier of the target account, organizational unit, or the root to disassociate from the specified configuration.</p>
    pub fn target(mut self, input: crate::types::Target) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identifier of the target account, organizational unit, or the root to disassociate from the specified configuration.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::Target>) -> Self {
        self.target = input;
        self
    }
    /// <p>The identifier of the target account, organizational unit, or the root to disassociate from the specified configuration.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::Target> {
        &self.target
    }
    /// <p>The Amazon Resource Name (ARN) of a configuration policy, the universally unique identifier (UUID) of a configuration policy, or a value of <code>SELF_MANAGED_SECURITY_HUB</code> for a self-managed configuration.</p>
    /// This field is required.
    pub fn configuration_policy_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_policy_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a configuration policy, the universally unique identifier (UUID) of a configuration policy, or a value of <code>SELF_MANAGED_SECURITY_HUB</code> for a self-managed configuration.</p>
    pub fn set_configuration_policy_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_policy_identifier = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a configuration policy, the universally unique identifier (UUID) of a configuration policy, or a value of <code>SELF_MANAGED_SECURITY_HUB</code> for a self-managed configuration.</p>
    pub fn get_configuration_policy_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_policy_identifier
    }
    /// Consumes the builder and constructs a [`StartConfigurationPolicyDisassociationInput`](crate::operation::start_configuration_policy_disassociation::StartConfigurationPolicyDisassociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_configuration_policy_disassociation::StartConfigurationPolicyDisassociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_configuration_policy_disassociation::StartConfigurationPolicyDisassociationInput {
                target: self.target,
                configuration_policy_identifier: self.configuration_policy_identifier,
            },
        )
    }
}
