// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAssetModelInput {
    /// <p>The ID of the asset model to delete. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub asset_model_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The expected current entity tag (ETag) for the asset model’s latest or active version (specified using <code>matchForVersionType</code>). The delete request is rejected if the tag does not match the latest or active version's current entity tag. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/opt-locking-for-model.html">Optimistic locking for asset model writes</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
    /// <p>Accepts <b>*</b> to reject the delete request if an active version (specified using <code>matchForVersionType</code> as <code>ACTIVE</code>) already exists for the asset model.</p>
    pub if_none_match: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the asset model version type (<code>LATEST</code> or <code>ACTIVE</code>) used in conjunction with <code>If-Match</code> or <code>If-None-Match</code> headers to determine the target ETag for the delete operation.</p>
    pub match_for_version_type: ::std::option::Option<crate::types::AssetModelVersionType>,
}
impl DeleteAssetModelInput {
    /// <p>The ID of the asset model to delete. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn asset_model_id(&self) -> ::std::option::Option<&str> {
        self.asset_model_id.as_deref()
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The expected current entity tag (ETag) for the asset model’s latest or active version (specified using <code>matchForVersionType</code>). The delete request is rejected if the tag does not match the latest or active version's current entity tag. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/opt-locking-for-model.html">Optimistic locking for asset model writes</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
    /// <p>Accepts <b>*</b> to reject the delete request if an active version (specified using <code>matchForVersionType</code> as <code>ACTIVE</code>) already exists for the asset model.</p>
    pub fn if_none_match(&self) -> ::std::option::Option<&str> {
        self.if_none_match.as_deref()
    }
    /// <p>Specifies the asset model version type (<code>LATEST</code> or <code>ACTIVE</code>) used in conjunction with <code>If-Match</code> or <code>If-None-Match</code> headers to determine the target ETag for the delete operation.</p>
    pub fn match_for_version_type(&self) -> ::std::option::Option<&crate::types::AssetModelVersionType> {
        self.match_for_version_type.as_ref()
    }
}
impl DeleteAssetModelInput {
    /// Creates a new builder-style object to manufacture [`DeleteAssetModelInput`](crate::operation::delete_asset_model::DeleteAssetModelInput).
    pub fn builder() -> crate::operation::delete_asset_model::builders::DeleteAssetModelInputBuilder {
        crate::operation::delete_asset_model::builders::DeleteAssetModelInputBuilder::default()
    }
}

/// A builder for [`DeleteAssetModelInput`](crate::operation::delete_asset_model::DeleteAssetModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAssetModelInputBuilder {
    pub(crate) asset_model_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
    pub(crate) if_none_match: ::std::option::Option<::std::string::String>,
    pub(crate) match_for_version_type: ::std::option::Option<crate::types::AssetModelVersionType>,
}
impl DeleteAssetModelInputBuilder {
    /// <p>The ID of the asset model to delete. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    /// This field is required.
    pub fn asset_model_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_model_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset model to delete. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_asset_model_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_model_id = input;
        self
    }
    /// <p>The ID of the asset model to delete. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_asset_model_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_model_id
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The expected current entity tag (ETag) for the asset model’s latest or active version (specified using <code>matchForVersionType</code>). The delete request is rejected if the tag does not match the latest or active version's current entity tag. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/opt-locking-for-model.html">Optimistic locking for asset model writes</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The expected current entity tag (ETag) for the asset model’s latest or active version (specified using <code>matchForVersionType</code>). The delete request is rejected if the tag does not match the latest or active version's current entity tag. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/opt-locking-for-model.html">Optimistic locking for asset model writes</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The expected current entity tag (ETag) for the asset model’s latest or active version (specified using <code>matchForVersionType</code>). The delete request is rejected if the tag does not match the latest or active version's current entity tag. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/opt-locking-for-model.html">Optimistic locking for asset model writes</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// <p>Accepts <b>*</b> to reject the delete request if an active version (specified using <code>matchForVersionType</code> as <code>ACTIVE</code>) already exists for the asset model.</p>
    pub fn if_none_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_none_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Accepts <b>*</b> to reject the delete request if an active version (specified using <code>matchForVersionType</code> as <code>ACTIVE</code>) already exists for the asset model.</p>
    pub fn set_if_none_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_none_match = input;
        self
    }
    /// <p>Accepts <b>*</b> to reject the delete request if an active version (specified using <code>matchForVersionType</code> as <code>ACTIVE</code>) already exists for the asset model.</p>
    pub fn get_if_none_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_none_match
    }
    /// <p>Specifies the asset model version type (<code>LATEST</code> or <code>ACTIVE</code>) used in conjunction with <code>If-Match</code> or <code>If-None-Match</code> headers to determine the target ETag for the delete operation.</p>
    pub fn match_for_version_type(mut self, input: crate::types::AssetModelVersionType) -> Self {
        self.match_for_version_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the asset model version type (<code>LATEST</code> or <code>ACTIVE</code>) used in conjunction with <code>If-Match</code> or <code>If-None-Match</code> headers to determine the target ETag for the delete operation.</p>
    pub fn set_match_for_version_type(mut self, input: ::std::option::Option<crate::types::AssetModelVersionType>) -> Self {
        self.match_for_version_type = input;
        self
    }
    /// <p>Specifies the asset model version type (<code>LATEST</code> or <code>ACTIVE</code>) used in conjunction with <code>If-Match</code> or <code>If-None-Match</code> headers to determine the target ETag for the delete operation.</p>
    pub fn get_match_for_version_type(&self) -> &::std::option::Option<crate::types::AssetModelVersionType> {
        &self.match_for_version_type
    }
    /// Consumes the builder and constructs a [`DeleteAssetModelInput`](crate::operation::delete_asset_model::DeleteAssetModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_asset_model::DeleteAssetModelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_asset_model::DeleteAssetModelInput {
            asset_model_id: self.asset_model_id,
            client_token: self.client_token,
            if_match: self.if_match,
            if_none_match: self.if_none_match,
            match_for_version_type: self.match_for_version_type,
        })
    }
}
