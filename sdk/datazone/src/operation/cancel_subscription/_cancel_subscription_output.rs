// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelSubscriptionOutput {
    /// <p>The identifier of the subscription.</p>
    pub id: ::std::string::String,
    /// <p>Specifies the Amazon DataZone user who is cancelling the subscription.</p>
    pub created_by: ::std::string::String,
    /// <p>The Amazon DataZone user that cancelled the subscription.</p>
    pub updated_by: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription is being cancelled.</p>
    pub domain_id: ::std::string::String,
    /// <p>The status of the request to cancel the subscription.</p>
    pub status: crate::types::SubscriptionStatus,
    /// <p>The timestamp that specifies when the request to cancel the subscription was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The timestamp that specifies when the subscription was cancelled.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>The Amazon DataZone user who is made a subscriber to the specified asset by the subscription that is being cancelled.</p>
    pub subscribed_principal: ::std::option::Option<crate::types::SubscribedPrincipal>,
    /// <p>The asset to which a subscription is being cancelled.</p>
    pub subscribed_listing: ::std::option::Option<crate::types::SubscribedListing>,
    /// <p>The unique ID of the subscripton request for the subscription that is being cancelled.</p>
    pub subscription_request_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the permissions to the asset are retained after the subscription is cancelled.</p>
    pub retain_permissions: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl CancelSubscriptionOutput {
    /// <p>The identifier of the subscription.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>Specifies the Amazon DataZone user who is cancelling the subscription.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The Amazon DataZone user that cancelled the subscription.</p>
    pub fn updated_by(&self) -> ::std::option::Option<&str> {
        self.updated_by.as_deref()
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription is being cancelled.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The status of the request to cancel the subscription.</p>
    pub fn status(&self) -> &crate::types::SubscriptionStatus {
        &self.status
    }
    /// <p>The timestamp that specifies when the request to cancel the subscription was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The timestamp that specifies when the subscription was cancelled.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>The Amazon DataZone user who is made a subscriber to the specified asset by the subscription that is being cancelled.</p>
    pub fn subscribed_principal(&self) -> ::std::option::Option<&crate::types::SubscribedPrincipal> {
        self.subscribed_principal.as_ref()
    }
    /// <p>The asset to which a subscription is being cancelled.</p>
    pub fn subscribed_listing(&self) -> ::std::option::Option<&crate::types::SubscribedListing> {
        self.subscribed_listing.as_ref()
    }
    /// <p>The unique ID of the subscripton request for the subscription that is being cancelled.</p>
    pub fn subscription_request_id(&self) -> ::std::option::Option<&str> {
        self.subscription_request_id.as_deref()
    }
    /// <p>Specifies whether the permissions to the asset are retained after the subscription is cancelled.</p>
    pub fn retain_permissions(&self) -> ::std::option::Option<bool> {
        self.retain_permissions
    }
}
impl ::aws_types::request_id::RequestId for CancelSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`CancelSubscriptionOutput`](crate::operation::cancel_subscription::CancelSubscriptionOutput).
    pub fn builder() -> crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder {
        crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`CancelSubscriptionOutput`](crate::operation::cancel_subscription::CancelSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelSubscriptionOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SubscriptionStatus>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) subscribed_principal: ::std::option::Option<crate::types::SubscribedPrincipal>,
    pub(crate) subscribed_listing: ::std::option::Option<crate::types::SubscribedListing>,
    pub(crate) subscription_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) retain_permissions: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl CancelSubscriptionOutputBuilder {
    /// <p>The identifier of the subscription.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the subscription.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Specifies the Amazon DataZone user who is cancelling the subscription.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon DataZone user who is cancelling the subscription.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>Specifies the Amazon DataZone user who is cancelling the subscription.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The Amazon DataZone user that cancelled the subscription.</p>
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon DataZone user that cancelled the subscription.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The Amazon DataZone user that cancelled the subscription.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription is being cancelled.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription is being cancelled.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription is being cancelled.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The status of the request to cancel the subscription.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::SubscriptionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the request to cancel the subscription.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SubscriptionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the request to cancel the subscription.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SubscriptionStatus> {
        &self.status
    }
    /// <p>The timestamp that specifies when the request to cancel the subscription was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that specifies when the request to cancel the subscription was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp that specifies when the request to cancel the subscription was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp that specifies when the subscription was cancelled.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that specifies when the subscription was cancelled.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp that specifies when the subscription was cancelled.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The Amazon DataZone user who is made a subscriber to the specified asset by the subscription that is being cancelled.</p>
    /// This field is required.
    pub fn subscribed_principal(mut self, input: crate::types::SubscribedPrincipal) -> Self {
        self.subscribed_principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon DataZone user who is made a subscriber to the specified asset by the subscription that is being cancelled.</p>
    pub fn set_subscribed_principal(mut self, input: ::std::option::Option<crate::types::SubscribedPrincipal>) -> Self {
        self.subscribed_principal = input;
        self
    }
    /// <p>The Amazon DataZone user who is made a subscriber to the specified asset by the subscription that is being cancelled.</p>
    pub fn get_subscribed_principal(&self) -> &::std::option::Option<crate::types::SubscribedPrincipal> {
        &self.subscribed_principal
    }
    /// <p>The asset to which a subscription is being cancelled.</p>
    /// This field is required.
    pub fn subscribed_listing(mut self, input: crate::types::SubscribedListing) -> Self {
        self.subscribed_listing = ::std::option::Option::Some(input);
        self
    }
    /// <p>The asset to which a subscription is being cancelled.</p>
    pub fn set_subscribed_listing(mut self, input: ::std::option::Option<crate::types::SubscribedListing>) -> Self {
        self.subscribed_listing = input;
        self
    }
    /// <p>The asset to which a subscription is being cancelled.</p>
    pub fn get_subscribed_listing(&self) -> &::std::option::Option<crate::types::SubscribedListing> {
        &self.subscribed_listing
    }
    /// <p>The unique ID of the subscripton request for the subscription that is being cancelled.</p>
    pub fn subscription_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the subscripton request for the subscription that is being cancelled.</p>
    pub fn set_subscription_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_request_id = input;
        self
    }
    /// <p>The unique ID of the subscripton request for the subscription that is being cancelled.</p>
    pub fn get_subscription_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_request_id
    }
    /// <p>Specifies whether the permissions to the asset are retained after the subscription is cancelled.</p>
    pub fn retain_permissions(mut self, input: bool) -> Self {
        self.retain_permissions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the permissions to the asset are retained after the subscription is cancelled.</p>
    pub fn set_retain_permissions(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retain_permissions = input;
        self
    }
    /// <p>Specifies whether the permissions to the asset are retained after the subscription is cancelled.</p>
    pub fn get_retain_permissions(&self) -> &::std::option::Option<bool> {
        &self.retain_permissions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelSubscriptionOutput`](crate::operation::cancel_subscription::CancelSubscriptionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::id)
    /// - [`created_by`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::created_by)
    /// - [`domain_id`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::domain_id)
    /// - [`status`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::status)
    /// - [`created_at`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::created_at)
    /// - [`updated_at`](crate::operation::cancel_subscription::builders::CancelSubscriptionOutputBuilder::updated_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_subscription::CancelSubscriptionOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::cancel_subscription::CancelSubscriptionOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            updated_by: self.updated_by,
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building CancelSubscriptionOutput",
                )
            })?,
            subscribed_principal: self.subscribed_principal,
            subscribed_listing: self.subscribed_listing,
            subscription_request_id: self.subscription_request_id,
            retain_permissions: self.retain_permissions,
            _request_id: self._request_id,
        })
    }
}
