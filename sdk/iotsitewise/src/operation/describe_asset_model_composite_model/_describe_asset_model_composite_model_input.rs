// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAssetModelCompositeModelInput {
    /// <p>The ID of the asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub asset_model_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of a composite model on this asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub asset_model_composite_model_id: ::std::option::Option<::std::string::String>,
    /// <p>The version alias that specifies the latest or active version of the asset model. The details are returned in the response. The default value is <code>LATEST</code>. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/model-active-version.html"> Asset model versions</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub asset_model_version: ::std::option::Option<::std::string::String>,
}
impl DescribeAssetModelCompositeModelInput {
    /// <p>The ID of the asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn asset_model_id(&self) -> ::std::option::Option<&str> {
        self.asset_model_id.as_deref()
    }
    /// <p>The ID of a composite model on this asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn asset_model_composite_model_id(&self) -> ::std::option::Option<&str> {
        self.asset_model_composite_model_id.as_deref()
    }
    /// <p>The version alias that specifies the latest or active version of the asset model. The details are returned in the response. The default value is <code>LATEST</code>. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/model-active-version.html"> Asset model versions</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn asset_model_version(&self) -> ::std::option::Option<&str> {
        self.asset_model_version.as_deref()
    }
}
impl DescribeAssetModelCompositeModelInput {
    /// Creates a new builder-style object to manufacture [`DescribeAssetModelCompositeModelInput`](crate::operation::describe_asset_model_composite_model::DescribeAssetModelCompositeModelInput).
    pub fn builder() -> crate::operation::describe_asset_model_composite_model::builders::DescribeAssetModelCompositeModelInputBuilder {
        crate::operation::describe_asset_model_composite_model::builders::DescribeAssetModelCompositeModelInputBuilder::default()
    }
}

/// A builder for [`DescribeAssetModelCompositeModelInput`](crate::operation::describe_asset_model_composite_model::DescribeAssetModelCompositeModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAssetModelCompositeModelInputBuilder {
    pub(crate) asset_model_id: ::std::option::Option<::std::string::String>,
    pub(crate) asset_model_composite_model_id: ::std::option::Option<::std::string::String>,
    pub(crate) asset_model_version: ::std::option::Option<::std::string::String>,
}
impl DescribeAssetModelCompositeModelInputBuilder {
    /// <p>The ID of the asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    /// This field is required.
    pub fn asset_model_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_model_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_asset_model_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_model_id = input;
        self
    }
    /// <p>The ID of the asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_asset_model_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_model_id
    }
    /// <p>The ID of a composite model on this asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    /// This field is required.
    pub fn asset_model_composite_model_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_model_composite_model_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of a composite model on this asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_asset_model_composite_model_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_model_composite_model_id = input;
        self
    }
    /// <p>The ID of a composite model on this asset model. This can be either the actual ID in UUID format, or else <code>externalId:</code> followed by the external ID, if it has one. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-id-references">Referencing objects with external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_asset_model_composite_model_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_model_composite_model_id
    }
    /// <p>The version alias that specifies the latest or active version of the asset model. The details are returned in the response. The default value is <code>LATEST</code>. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/model-active-version.html"> Asset model versions</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn asset_model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version alias that specifies the latest or active version of the asset model. The details are returned in the response. The default value is <code>LATEST</code>. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/model-active-version.html"> Asset model versions</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_asset_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_model_version = input;
        self
    }
    /// <p>The version alias that specifies the latest or active version of the asset model. The details are returned in the response. The default value is <code>LATEST</code>. See <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/model-active-version.html"> Asset model versions</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_asset_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_model_version
    }
    /// Consumes the builder and constructs a [`DescribeAssetModelCompositeModelInput`](crate::operation::describe_asset_model_composite_model::DescribeAssetModelCompositeModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_asset_model_composite_model::DescribeAssetModelCompositeModelInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_asset_model_composite_model::DescribeAssetModelCompositeModelInput {
                asset_model_id: self.asset_model_id,
                asset_model_composite_model_id: self.asset_model_composite_model_id,
                asset_model_version: self.asset_model_version,
            },
        )
    }
}
