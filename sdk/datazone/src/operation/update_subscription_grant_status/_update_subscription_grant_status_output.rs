// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSubscriptionGrantStatusOutput {
    /// <p>The identifier of the subscription grant.</p>
    pub id: ::std::string::String,
    /// <p>The Amazon DataZone domain user who created the subscription grant status.</p>
    pub created_by: ::std::string::String,
    /// <p>The Amazon DataZone user who updated the subscription grant status.</p>
    pub updated_by: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon DataZone domain in which a subscription grant status is to be updated.</p>
    pub domain_id: ::std::string::String,
    /// <p>The timestamp of when the subscription grant status was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The timestamp of when the subscription grant status is to be updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>The identifier of the subscription target whose subscription grant status is to be updated.</p>
    pub subscription_target_id: ::std::string::String,
    /// <p>The granted entity to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub granted_entity: ::std::option::Option<crate::types::GrantedEntity>,
    /// <p>The status to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub status: crate::types::SubscriptionGrantOverallStatus,
    /// <p>The details of the asset for which the subscription grant is created.</p>
    pub assets: ::std::option::Option<::std::vec::Vec<crate::types::SubscribedAsset>>,
    /// <p>The identifier of the subscription.</p>
    #[deprecated(note = "Multiple subscriptions can exist for a single grant")]
    pub subscription_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateSubscriptionGrantStatusOutput {
    /// <p>The identifier of the subscription grant.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The Amazon DataZone domain user who created the subscription grant status.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The Amazon DataZone user who updated the subscription grant status.</p>
    pub fn updated_by(&self) -> ::std::option::Option<&str> {
        self.updated_by.as_deref()
    }
    /// <p>The identifier of the Amazon DataZone domain in which a subscription grant status is to be updated.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The timestamp of when the subscription grant status was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The timestamp of when the subscription grant status is to be updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>The identifier of the subscription target whose subscription grant status is to be updated.</p>
    pub fn subscription_target_id(&self) -> &str {
        use std::ops::Deref;
        self.subscription_target_id.deref()
    }
    /// <p>The granted entity to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn granted_entity(&self) -> ::std::option::Option<&crate::types::GrantedEntity> {
        self.granted_entity.as_ref()
    }
    /// <p>The status to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn status(&self) -> &crate::types::SubscriptionGrantOverallStatus {
        &self.status
    }
    /// <p>The details of the asset for which the subscription grant is created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.assets.is_none()`.
    pub fn assets(&self) -> &[crate::types::SubscribedAsset] {
        self.assets.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of the subscription.</p>
    #[deprecated(note = "Multiple subscriptions can exist for a single grant")]
    pub fn subscription_id(&self) -> ::std::option::Option<&str> {
        self.subscription_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSubscriptionGrantStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSubscriptionGrantStatusOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSubscriptionGrantStatusOutput`](crate::operation::update_subscription_grant_status::UpdateSubscriptionGrantStatusOutput).
    pub fn builder() -> crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder {
        crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::default()
    }
}

/// A builder for [`UpdateSubscriptionGrantStatusOutput`](crate::operation::update_subscription_grant_status::UpdateSubscriptionGrantStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSubscriptionGrantStatusOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) subscription_target_id: ::std::option::Option<::std::string::String>,
    pub(crate) granted_entity: ::std::option::Option<crate::types::GrantedEntity>,
    pub(crate) status: ::std::option::Option<crate::types::SubscriptionGrantOverallStatus>,
    pub(crate) assets: ::std::option::Option<::std::vec::Vec<crate::types::SubscribedAsset>>,
    pub(crate) subscription_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateSubscriptionGrantStatusOutputBuilder {
    /// <p>The identifier of the subscription grant.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription grant.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the subscription grant.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon DataZone domain user who created the subscription grant status.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon DataZone domain user who created the subscription grant status.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The Amazon DataZone domain user who created the subscription grant status.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The Amazon DataZone user who updated the subscription grant status.</p>
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon DataZone user who updated the subscription grant status.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The Amazon DataZone user who updated the subscription grant status.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    /// <p>The identifier of the Amazon DataZone domain in which a subscription grant status is to be updated.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which a subscription grant status is to be updated.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which a subscription grant status is to be updated.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The timestamp of when the subscription grant status was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the subscription grant status was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the subscription grant status was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp of when the subscription grant status is to be updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the subscription grant status is to be updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp of when the subscription grant status is to be updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The identifier of the subscription target whose subscription grant status is to be updated.</p>
    /// This field is required.
    pub fn subscription_target_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_target_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription target whose subscription grant status is to be updated.</p>
    pub fn set_subscription_target_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_target_id = input;
        self
    }
    /// <p>The identifier of the subscription target whose subscription grant status is to be updated.</p>
    pub fn get_subscription_target_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_target_id
    }
    /// <p>The granted entity to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    /// This field is required.
    pub fn granted_entity(mut self, input: crate::types::GrantedEntity) -> Self {
        self.granted_entity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The granted entity to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn set_granted_entity(mut self, input: ::std::option::Option<crate::types::GrantedEntity>) -> Self {
        self.granted_entity = input;
        self
    }
    /// <p>The granted entity to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn get_granted_entity(&self) -> &::std::option::Option<crate::types::GrantedEntity> {
        &self.granted_entity
    }
    /// <p>The status to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::SubscriptionGrantOverallStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SubscriptionGrantOverallStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status to be updated as part of the <code>UpdateSubscriptionGrantStatus</code> action.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SubscriptionGrantOverallStatus> {
        &self.status
    }
    /// Appends an item to `assets`.
    ///
    /// To override the contents of this collection use [`set_assets`](Self::set_assets).
    ///
    /// <p>The details of the asset for which the subscription grant is created.</p>
    pub fn assets(mut self, input: crate::types::SubscribedAsset) -> Self {
        let mut v = self.assets.unwrap_or_default();
        v.push(input);
        self.assets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details of the asset for which the subscription grant is created.</p>
    pub fn set_assets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SubscribedAsset>>) -> Self {
        self.assets = input;
        self
    }
    /// <p>The details of the asset for which the subscription grant is created.</p>
    pub fn get_assets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SubscribedAsset>> {
        &self.assets
    }
    /// <p>The identifier of the subscription.</p>
    #[deprecated(note = "Multiple subscriptions can exist for a single grant")]
    pub fn subscription_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription.</p>
    #[deprecated(note = "Multiple subscriptions can exist for a single grant")]
    pub fn set_subscription_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_id = input;
        self
    }
    /// <p>The identifier of the subscription.</p>
    #[deprecated(note = "Multiple subscriptions can exist for a single grant")]
    pub fn get_subscription_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateSubscriptionGrantStatusOutput`](crate::operation::update_subscription_grant_status::UpdateSubscriptionGrantStatusOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::id)
    /// - [`created_by`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::created_by)
    /// - [`domain_id`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::domain_id)
    /// - [`created_at`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::created_at)
    /// - [`updated_at`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::updated_at)
    /// - [`subscription_target_id`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::subscription_target_id)
    /// - [`status`](crate::operation::update_subscription_grant_status::builders::UpdateSubscriptionGrantStatusOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_subscription_grant_status::UpdateSubscriptionGrantStatusOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_subscription_grant_status::UpdateSubscriptionGrantStatusOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            updated_by: self.updated_by,
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            subscription_target_id: self.subscription_target_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subscription_target_id",
                    "subscription_target_id was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            granted_entity: self.granted_entity,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building UpdateSubscriptionGrantStatusOutput",
                )
            })?,
            assets: self.assets,
            subscription_id: self.subscription_id,
            _request_id: self._request_id,
        })
    }
}
