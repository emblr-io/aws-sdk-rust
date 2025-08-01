// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the asset for which the subscription grant is created.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SubscribedAsset {
    /// <p>The identifier of the asset for which the subscription grant is created.</p>
    pub asset_id: ::std::string::String,
    /// <p>The revision of the asset for which the subscription grant is created.</p>
    pub asset_revision: ::std::string::String,
    /// <p>The status of the asset for which the subscription grant is created.</p>
    pub status: crate::types::SubscriptionGrantStatus,
    /// <p>The target name of the asset for which the subscription grant is created.</p>
    pub target_name: ::std::option::Option<::std::string::String>,
    /// <p>The failure cause included in the details of the asset for which the subscription grant is created.</p>
    pub failure_cause: ::std::option::Option<crate::types::FailureCause>,
    /// <p>The timestamp of when the subscription grant to the asset is created.</p>
    pub granted_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The failure timestamp included in the details of the asset for which the subscription grant is created.</p>
    pub failure_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The asset scope of the subscribed asset.</p>
    pub asset_scope: ::std::option::Option<crate::types::AssetScope>,
}
impl SubscribedAsset {
    /// <p>The identifier of the asset for which the subscription grant is created.</p>
    pub fn asset_id(&self) -> &str {
        use std::ops::Deref;
        self.asset_id.deref()
    }
    /// <p>The revision of the asset for which the subscription grant is created.</p>
    pub fn asset_revision(&self) -> &str {
        use std::ops::Deref;
        self.asset_revision.deref()
    }
    /// <p>The status of the asset for which the subscription grant is created.</p>
    pub fn status(&self) -> &crate::types::SubscriptionGrantStatus {
        &self.status
    }
    /// <p>The target name of the asset for which the subscription grant is created.</p>
    pub fn target_name(&self) -> ::std::option::Option<&str> {
        self.target_name.as_deref()
    }
    /// <p>The failure cause included in the details of the asset for which the subscription grant is created.</p>
    pub fn failure_cause(&self) -> ::std::option::Option<&crate::types::FailureCause> {
        self.failure_cause.as_ref()
    }
    /// <p>The timestamp of when the subscription grant to the asset is created.</p>
    pub fn granted_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.granted_timestamp.as_ref()
    }
    /// <p>The failure timestamp included in the details of the asset for which the subscription grant is created.</p>
    pub fn failure_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.failure_timestamp.as_ref()
    }
    /// <p>The asset scope of the subscribed asset.</p>
    pub fn asset_scope(&self) -> ::std::option::Option<&crate::types::AssetScope> {
        self.asset_scope.as_ref()
    }
}
impl SubscribedAsset {
    /// Creates a new builder-style object to manufacture [`SubscribedAsset`](crate::types::SubscribedAsset).
    pub fn builder() -> crate::types::builders::SubscribedAssetBuilder {
        crate::types::builders::SubscribedAssetBuilder::default()
    }
}

/// A builder for [`SubscribedAsset`](crate::types::SubscribedAsset).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubscribedAssetBuilder {
    pub(crate) asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) asset_revision: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SubscriptionGrantStatus>,
    pub(crate) target_name: ::std::option::Option<::std::string::String>,
    pub(crate) failure_cause: ::std::option::Option<crate::types::FailureCause>,
    pub(crate) granted_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) failure_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) asset_scope: ::std::option::Option<crate::types::AssetScope>,
}
impl SubscribedAssetBuilder {
    /// <p>The identifier of the asset for which the subscription grant is created.</p>
    /// This field is required.
    pub fn asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the asset for which the subscription grant is created.</p>
    pub fn set_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_id = input;
        self
    }
    /// <p>The identifier of the asset for which the subscription grant is created.</p>
    pub fn get_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_id
    }
    /// <p>The revision of the asset for which the subscription grant is created.</p>
    /// This field is required.
    pub fn asset_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision of the asset for which the subscription grant is created.</p>
    pub fn set_asset_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_revision = input;
        self
    }
    /// <p>The revision of the asset for which the subscription grant is created.</p>
    pub fn get_asset_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_revision
    }
    /// <p>The status of the asset for which the subscription grant is created.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::SubscriptionGrantStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the asset for which the subscription grant is created.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SubscriptionGrantStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the asset for which the subscription grant is created.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SubscriptionGrantStatus> {
        &self.status
    }
    /// <p>The target name of the asset for which the subscription grant is created.</p>
    pub fn target_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target name of the asset for which the subscription grant is created.</p>
    pub fn set_target_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_name = input;
        self
    }
    /// <p>The target name of the asset for which the subscription grant is created.</p>
    pub fn get_target_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_name
    }
    /// <p>The failure cause included in the details of the asset for which the subscription grant is created.</p>
    pub fn failure_cause(mut self, input: crate::types::FailureCause) -> Self {
        self.failure_cause = ::std::option::Option::Some(input);
        self
    }
    /// <p>The failure cause included in the details of the asset for which the subscription grant is created.</p>
    pub fn set_failure_cause(mut self, input: ::std::option::Option<crate::types::FailureCause>) -> Self {
        self.failure_cause = input;
        self
    }
    /// <p>The failure cause included in the details of the asset for which the subscription grant is created.</p>
    pub fn get_failure_cause(&self) -> &::std::option::Option<crate::types::FailureCause> {
        &self.failure_cause
    }
    /// <p>The timestamp of when the subscription grant to the asset is created.</p>
    pub fn granted_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.granted_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the subscription grant to the asset is created.</p>
    pub fn set_granted_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.granted_timestamp = input;
        self
    }
    /// <p>The timestamp of when the subscription grant to the asset is created.</p>
    pub fn get_granted_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.granted_timestamp
    }
    /// <p>The failure timestamp included in the details of the asset for which the subscription grant is created.</p>
    pub fn failure_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.failure_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The failure timestamp included in the details of the asset for which the subscription grant is created.</p>
    pub fn set_failure_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.failure_timestamp = input;
        self
    }
    /// <p>The failure timestamp included in the details of the asset for which the subscription grant is created.</p>
    pub fn get_failure_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.failure_timestamp
    }
    /// <p>The asset scope of the subscribed asset.</p>
    pub fn asset_scope(mut self, input: crate::types::AssetScope) -> Self {
        self.asset_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>The asset scope of the subscribed asset.</p>
    pub fn set_asset_scope(mut self, input: ::std::option::Option<crate::types::AssetScope>) -> Self {
        self.asset_scope = input;
        self
    }
    /// <p>The asset scope of the subscribed asset.</p>
    pub fn get_asset_scope(&self) -> &::std::option::Option<crate::types::AssetScope> {
        &self.asset_scope
    }
    /// Consumes the builder and constructs a [`SubscribedAsset`](crate::types::SubscribedAsset).
    /// This method will fail if any of the following fields are not set:
    /// - [`asset_id`](crate::types::builders::SubscribedAssetBuilder::asset_id)
    /// - [`asset_revision`](crate::types::builders::SubscribedAssetBuilder::asset_revision)
    /// - [`status`](crate::types::builders::SubscribedAssetBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::SubscribedAsset, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SubscribedAsset {
            asset_id: self.asset_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "asset_id",
                    "asset_id was not specified but it is required when building SubscribedAsset",
                )
            })?,
            asset_revision: self.asset_revision.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "asset_revision",
                    "asset_revision was not specified but it is required when building SubscribedAsset",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building SubscribedAsset",
                )
            })?,
            target_name: self.target_name,
            failure_cause: self.failure_cause,
            granted_timestamp: self.granted_timestamp,
            failure_timestamp: self.failure_timestamp,
            asset_scope: self.asset_scope,
        })
    }
}
