// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdatePartnerAppInput {
    /// <p>The ARN of the SageMaker Partner AI App to update.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Maintenance configuration settings for the SageMaker Partner AI App.</p>
    pub maintenance_config: ::std::option::Option<crate::types::PartnerAppMaintenanceConfig>,
    /// <p>Indicates the instance type and size of the cluster attached to the SageMaker Partner AI App.</p>
    pub tier: ::std::option::Option<::std::string::String>,
    /// <p>Configuration settings for the SageMaker Partner AI App.</p>
    pub application_config: ::std::option::Option<crate::types::PartnerAppConfig>,
    /// <p>When set to <code>TRUE</code>, the SageMaker Partner AI App sets the Amazon Web Services IAM session name or the authenticated IAM user as the identity of the SageMaker Partner AI App user.</p>
    pub enable_iam_session_based_identity: ::std::option::Option<bool>,
    /// <p>A unique token that guarantees that the call to this API is idempotent.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Each tag consists of a key and an optional value. Tag keys must be unique per resource.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UpdatePartnerAppInput {
    /// <p>The ARN of the SageMaker Partner AI App to update.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Maintenance configuration settings for the SageMaker Partner AI App.</p>
    pub fn maintenance_config(&self) -> ::std::option::Option<&crate::types::PartnerAppMaintenanceConfig> {
        self.maintenance_config.as_ref()
    }
    /// <p>Indicates the instance type and size of the cluster attached to the SageMaker Partner AI App.</p>
    pub fn tier(&self) -> ::std::option::Option<&str> {
        self.tier.as_deref()
    }
    /// <p>Configuration settings for the SageMaker Partner AI App.</p>
    pub fn application_config(&self) -> ::std::option::Option<&crate::types::PartnerAppConfig> {
        self.application_config.as_ref()
    }
    /// <p>When set to <code>TRUE</code>, the SageMaker Partner AI App sets the Amazon Web Services IAM session name or the authenticated IAM user as the identity of the SageMaker Partner AI App user.</p>
    pub fn enable_iam_session_based_identity(&self) -> ::std::option::Option<bool> {
        self.enable_iam_session_based_identity
    }
    /// <p>A unique token that guarantees that the call to this API is idempotent.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Each tag consists of a key and an optional value. Tag keys must be unique per resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl UpdatePartnerAppInput {
    /// Creates a new builder-style object to manufacture [`UpdatePartnerAppInput`](crate::operation::update_partner_app::UpdatePartnerAppInput).
    pub fn builder() -> crate::operation::update_partner_app::builders::UpdatePartnerAppInputBuilder {
        crate::operation::update_partner_app::builders::UpdatePartnerAppInputBuilder::default()
    }
}

/// A builder for [`UpdatePartnerAppInput`](crate::operation::update_partner_app::UpdatePartnerAppInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdatePartnerAppInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) maintenance_config: ::std::option::Option<crate::types::PartnerAppMaintenanceConfig>,
    pub(crate) tier: ::std::option::Option<::std::string::String>,
    pub(crate) application_config: ::std::option::Option<crate::types::PartnerAppConfig>,
    pub(crate) enable_iam_session_based_identity: ::std::option::Option<bool>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UpdatePartnerAppInputBuilder {
    /// <p>The ARN of the SageMaker Partner AI App to update.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the SageMaker Partner AI App to update.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the SageMaker Partner AI App to update.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Maintenance configuration settings for the SageMaker Partner AI App.</p>
    pub fn maintenance_config(mut self, input: crate::types::PartnerAppMaintenanceConfig) -> Self {
        self.maintenance_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maintenance configuration settings for the SageMaker Partner AI App.</p>
    pub fn set_maintenance_config(mut self, input: ::std::option::Option<crate::types::PartnerAppMaintenanceConfig>) -> Self {
        self.maintenance_config = input;
        self
    }
    /// <p>Maintenance configuration settings for the SageMaker Partner AI App.</p>
    pub fn get_maintenance_config(&self) -> &::std::option::Option<crate::types::PartnerAppMaintenanceConfig> {
        &self.maintenance_config
    }
    /// <p>Indicates the instance type and size of the cluster attached to the SageMaker Partner AI App.</p>
    pub fn tier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the instance type and size of the cluster attached to the SageMaker Partner AI App.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tier = input;
        self
    }
    /// <p>Indicates the instance type and size of the cluster attached to the SageMaker Partner AI App.</p>
    pub fn get_tier(&self) -> &::std::option::Option<::std::string::String> {
        &self.tier
    }
    /// <p>Configuration settings for the SageMaker Partner AI App.</p>
    pub fn application_config(mut self, input: crate::types::PartnerAppConfig) -> Self {
        self.application_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration settings for the SageMaker Partner AI App.</p>
    pub fn set_application_config(mut self, input: ::std::option::Option<crate::types::PartnerAppConfig>) -> Self {
        self.application_config = input;
        self
    }
    /// <p>Configuration settings for the SageMaker Partner AI App.</p>
    pub fn get_application_config(&self) -> &::std::option::Option<crate::types::PartnerAppConfig> {
        &self.application_config
    }
    /// <p>When set to <code>TRUE</code>, the SageMaker Partner AI App sets the Amazon Web Services IAM session name or the authenticated IAM user as the identity of the SageMaker Partner AI App user.</p>
    pub fn enable_iam_session_based_identity(mut self, input: bool) -> Self {
        self.enable_iam_session_based_identity = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to <code>TRUE</code>, the SageMaker Partner AI App sets the Amazon Web Services IAM session name or the authenticated IAM user as the identity of the SageMaker Partner AI App user.</p>
    pub fn set_enable_iam_session_based_identity(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_iam_session_based_identity = input;
        self
    }
    /// <p>When set to <code>TRUE</code>, the SageMaker Partner AI App sets the Amazon Web Services IAM session name or the authenticated IAM user as the identity of the SageMaker Partner AI App user.</p>
    pub fn get_enable_iam_session_based_identity(&self) -> &::std::option::Option<bool> {
        &self.enable_iam_session_based_identity
    }
    /// <p>A unique token that guarantees that the call to this API is idempotent.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique token that guarantees that the call to this API is idempotent.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique token that guarantees that the call to this API is idempotent.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Each tag consists of a key and an optional value. Tag keys must be unique per resource.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Each tag consists of a key and an optional value. Tag keys must be unique per resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Each tag consists of a key and an optional value. Tag keys must be unique per resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`UpdatePartnerAppInput`](crate::operation::update_partner_app::UpdatePartnerAppInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_partner_app::UpdatePartnerAppInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_partner_app::UpdatePartnerAppInput {
            arn: self.arn,
            maintenance_config: self.maintenance_config,
            tier: self.tier,
            application_config: self.application_config,
            enable_iam_session_based_identity: self.enable_iam_session_based_identity,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
