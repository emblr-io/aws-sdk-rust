// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The AWS IoT SiteWise soucre configuration filter.\[need held with desc here\]</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum IotSiteWiseSourceConfigurationFilter {
    /// <p>Filter by asset.</p>
    FilterByAsset(crate::types::FilterByAsset),
    /// <p>Filter by asset model.</p>
    FilterByAssetModel(crate::types::FilterByAssetModel),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl IotSiteWiseSourceConfigurationFilter {
    /// Tries to convert the enum instance into [`FilterByAsset`](crate::types::IotSiteWiseSourceConfigurationFilter::FilterByAsset), extracting the inner [`FilterByAsset`](crate::types::FilterByAsset).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_filter_by_asset(&self) -> ::std::result::Result<&crate::types::FilterByAsset, &Self> {
        if let IotSiteWiseSourceConfigurationFilter::FilterByAsset(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FilterByAsset`](crate::types::IotSiteWiseSourceConfigurationFilter::FilterByAsset).
    pub fn is_filter_by_asset(&self) -> bool {
        self.as_filter_by_asset().is_ok()
    }
    /// Tries to convert the enum instance into [`FilterByAssetModel`](crate::types::IotSiteWiseSourceConfigurationFilter::FilterByAssetModel), extracting the inner [`FilterByAssetModel`](crate::types::FilterByAssetModel).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_filter_by_asset_model(&self) -> ::std::result::Result<&crate::types::FilterByAssetModel, &Self> {
        if let IotSiteWiseSourceConfigurationFilter::FilterByAssetModel(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FilterByAssetModel`](crate::types::IotSiteWiseSourceConfigurationFilter::FilterByAssetModel).
    pub fn is_filter_by_asset_model(&self) -> bool {
        self.as_filter_by_asset_model().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
