// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the search results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum SearchInventoryResultItem {
    /// <p>The asset item included in the search results.</p>
    AssetItem(crate::types::AssetItem),
    /// <p>The data product.</p>
    DataProductItem(crate::types::DataProductResultItem),
    /// <p>The glossary item included in the search results.</p>
    GlossaryItem(crate::types::GlossaryItem),
    /// <p>The glossary term item included in the search results.</p>
    GlossaryTermItem(crate::types::GlossaryTermItem),
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
impl SearchInventoryResultItem {
    /// Tries to convert the enum instance into [`AssetItem`](crate::types::SearchInventoryResultItem::AssetItem), extracting the inner [`AssetItem`](crate::types::AssetItem).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_asset_item(&self) -> ::std::result::Result<&crate::types::AssetItem, &Self> {
        if let SearchInventoryResultItem::AssetItem(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AssetItem`](crate::types::SearchInventoryResultItem::AssetItem).
    pub fn is_asset_item(&self) -> bool {
        self.as_asset_item().is_ok()
    }
    /// Tries to convert the enum instance into [`DataProductItem`](crate::types::SearchInventoryResultItem::DataProductItem), extracting the inner [`DataProductResultItem`](crate::types::DataProductResultItem).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_data_product_item(&self) -> ::std::result::Result<&crate::types::DataProductResultItem, &Self> {
        if let SearchInventoryResultItem::DataProductItem(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DataProductItem`](crate::types::SearchInventoryResultItem::DataProductItem).
    pub fn is_data_product_item(&self) -> bool {
        self.as_data_product_item().is_ok()
    }
    /// Tries to convert the enum instance into [`GlossaryItem`](crate::types::SearchInventoryResultItem::GlossaryItem), extracting the inner [`GlossaryItem`](crate::types::GlossaryItem).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_glossary_item(&self) -> ::std::result::Result<&crate::types::GlossaryItem, &Self> {
        if let SearchInventoryResultItem::GlossaryItem(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GlossaryItem`](crate::types::SearchInventoryResultItem::GlossaryItem).
    pub fn is_glossary_item(&self) -> bool {
        self.as_glossary_item().is_ok()
    }
    /// Tries to convert the enum instance into [`GlossaryTermItem`](crate::types::SearchInventoryResultItem::GlossaryTermItem), extracting the inner [`GlossaryTermItem`](crate::types::GlossaryTermItem).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_glossary_term_item(&self) -> ::std::result::Result<&crate::types::GlossaryTermItem, &Self> {
        if let SearchInventoryResultItem::GlossaryTermItem(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GlossaryTermItem`](crate::types::SearchInventoryResultItem::GlossaryTermItem).
    pub fn is_glossary_term_item(&self) -> bool {
        self.as_glossary_term_item().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
