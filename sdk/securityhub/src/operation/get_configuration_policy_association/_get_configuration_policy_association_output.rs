// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfigurationPolicyAssociationOutput {
    /// <p>The universally unique identifier (UUID) of a configuration policy. For self-managed behavior, the value is <code>SELF_MANAGED_SECURITY_HUB</code>.</p>
    pub configuration_policy_id: ::std::option::Option<::std::string::String>,
    /// <p>The target account ID, organizational unit ID, or the root ID for which the association is retrieved.</p>
    pub target_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the target is an Amazon Web Services account, organizational unit, or the organization root.</p>
    pub target_type: ::std::option::Option<crate::types::TargetType>,
    /// <p>Indicates whether the association between the specified target and the configuration was directly applied by the Security Hub delegated administrator or inherited from a parent.</p>
    pub association_type: ::std::option::Option<crate::types::AssociationType>,
    /// <p>The date and time, in UTC and ISO 8601 format, that the configuration policy association was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current status of the association between the specified target and the configuration.</p>
    pub association_status: ::std::option::Option<crate::types::ConfigurationPolicyAssociationStatus>,
    /// <p>The explanation for a <code>FAILED</code> value for <code>AssociationStatus</code>.</p>
    pub association_status_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetConfigurationPolicyAssociationOutput {
    /// <p>The universally unique identifier (UUID) of a configuration policy. For self-managed behavior, the value is <code>SELF_MANAGED_SECURITY_HUB</code>.</p>
    pub fn configuration_policy_id(&self) -> ::std::option::Option<&str> {
        self.configuration_policy_id.as_deref()
    }
    /// <p>The target account ID, organizational unit ID, or the root ID for which the association is retrieved.</p>
    pub fn target_id(&self) -> ::std::option::Option<&str> {
        self.target_id.as_deref()
    }
    /// <p>Specifies whether the target is an Amazon Web Services account, organizational unit, or the organization root.</p>
    pub fn target_type(&self) -> ::std::option::Option<&crate::types::TargetType> {
        self.target_type.as_ref()
    }
    /// <p>Indicates whether the association between the specified target and the configuration was directly applied by the Security Hub delegated administrator or inherited from a parent.</p>
    pub fn association_type(&self) -> ::std::option::Option<&crate::types::AssociationType> {
        self.association_type.as_ref()
    }
    /// <p>The date and time, in UTC and ISO 8601 format, that the configuration policy association was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The current status of the association between the specified target and the configuration.</p>
    pub fn association_status(&self) -> ::std::option::Option<&crate::types::ConfigurationPolicyAssociationStatus> {
        self.association_status.as_ref()
    }
    /// <p>The explanation for a <code>FAILED</code> value for <code>AssociationStatus</code>.</p>
    pub fn association_status_message(&self) -> ::std::option::Option<&str> {
        self.association_status_message.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetConfigurationPolicyAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetConfigurationPolicyAssociationOutput {
    /// Creates a new builder-style object to manufacture [`GetConfigurationPolicyAssociationOutput`](crate::operation::get_configuration_policy_association::GetConfigurationPolicyAssociationOutput).
    pub fn builder() -> crate::operation::get_configuration_policy_association::builders::GetConfigurationPolicyAssociationOutputBuilder {
        crate::operation::get_configuration_policy_association::builders::GetConfigurationPolicyAssociationOutputBuilder::default()
    }
}

/// A builder for [`GetConfigurationPolicyAssociationOutput`](crate::operation::get_configuration_policy_association::GetConfigurationPolicyAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfigurationPolicyAssociationOutputBuilder {
    pub(crate) configuration_policy_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_type: ::std::option::Option<crate::types::TargetType>,
    pub(crate) association_type: ::std::option::Option<crate::types::AssociationType>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) association_status: ::std::option::Option<crate::types::ConfigurationPolicyAssociationStatus>,
    pub(crate) association_status_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetConfigurationPolicyAssociationOutputBuilder {
    /// <p>The universally unique identifier (UUID) of a configuration policy. For self-managed behavior, the value is <code>SELF_MANAGED_SECURITY_HUB</code>.</p>
    pub fn configuration_policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The universally unique identifier (UUID) of a configuration policy. For self-managed behavior, the value is <code>SELF_MANAGED_SECURITY_HUB</code>.</p>
    pub fn set_configuration_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_policy_id = input;
        self
    }
    /// <p>The universally unique identifier (UUID) of a configuration policy. For self-managed behavior, the value is <code>SELF_MANAGED_SECURITY_HUB</code>.</p>
    pub fn get_configuration_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_policy_id
    }
    /// <p>The target account ID, organizational unit ID, or the root ID for which the association is retrieved.</p>
    pub fn target_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target account ID, organizational unit ID, or the root ID for which the association is retrieved.</p>
    pub fn set_target_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_id = input;
        self
    }
    /// <p>The target account ID, organizational unit ID, or the root ID for which the association is retrieved.</p>
    pub fn get_target_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_id
    }
    /// <p>Specifies whether the target is an Amazon Web Services account, organizational unit, or the organization root.</p>
    pub fn target_type(mut self, input: crate::types::TargetType) -> Self {
        self.target_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the target is an Amazon Web Services account, organizational unit, or the organization root.</p>
    pub fn set_target_type(mut self, input: ::std::option::Option<crate::types::TargetType>) -> Self {
        self.target_type = input;
        self
    }
    /// <p>Specifies whether the target is an Amazon Web Services account, organizational unit, or the organization root.</p>
    pub fn get_target_type(&self) -> &::std::option::Option<crate::types::TargetType> {
        &self.target_type
    }
    /// <p>Indicates whether the association between the specified target and the configuration was directly applied by the Security Hub delegated administrator or inherited from a parent.</p>
    pub fn association_type(mut self, input: crate::types::AssociationType) -> Self {
        self.association_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the association between the specified target and the configuration was directly applied by the Security Hub delegated administrator or inherited from a parent.</p>
    pub fn set_association_type(mut self, input: ::std::option::Option<crate::types::AssociationType>) -> Self {
        self.association_type = input;
        self
    }
    /// <p>Indicates whether the association between the specified target and the configuration was directly applied by the Security Hub delegated administrator or inherited from a parent.</p>
    pub fn get_association_type(&self) -> &::std::option::Option<crate::types::AssociationType> {
        &self.association_type
    }
    /// <p>The date and time, in UTC and ISO 8601 format, that the configuration policy association was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and ISO 8601 format, that the configuration policy association was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time, in UTC and ISO 8601 format, that the configuration policy association was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The current status of the association between the specified target and the configuration.</p>
    pub fn association_status(mut self, input: crate::types::ConfigurationPolicyAssociationStatus) -> Self {
        self.association_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the association between the specified target and the configuration.</p>
    pub fn set_association_status(mut self, input: ::std::option::Option<crate::types::ConfigurationPolicyAssociationStatus>) -> Self {
        self.association_status = input;
        self
    }
    /// <p>The current status of the association between the specified target and the configuration.</p>
    pub fn get_association_status(&self) -> &::std::option::Option<crate::types::ConfigurationPolicyAssociationStatus> {
        &self.association_status
    }
    /// <p>The explanation for a <code>FAILED</code> value for <code>AssociationStatus</code>.</p>
    pub fn association_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The explanation for a <code>FAILED</code> value for <code>AssociationStatus</code>.</p>
    pub fn set_association_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_status_message = input;
        self
    }
    /// <p>The explanation for a <code>FAILED</code> value for <code>AssociationStatus</code>.</p>
    pub fn get_association_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_status_message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetConfigurationPolicyAssociationOutput`](crate::operation::get_configuration_policy_association::GetConfigurationPolicyAssociationOutput).
    pub fn build(self) -> crate::operation::get_configuration_policy_association::GetConfigurationPolicyAssociationOutput {
        crate::operation::get_configuration_policy_association::GetConfigurationPolicyAssociationOutput {
            configuration_policy_id: self.configuration_policy_id,
            target_id: self.target_id,
            target_type: self.target_type,
            association_type: self.association_type,
            updated_at: self.updated_at,
            association_status: self.association_status,
            association_status_message: self.association_status_message,
            _request_id: self._request_id,
        }
    }
}
