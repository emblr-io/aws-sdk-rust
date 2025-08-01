// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the related item you're adding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum RelatedItemsUpdate {
    /// <p>Details about the related item you're adding.</p>
    ItemToAdd(crate::types::RelatedItem),
    /// <p>Details about the related item you're deleting.</p>
    ItemToRemove(crate::types::ItemIdentifier),
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
impl RelatedItemsUpdate {
    /// Tries to convert the enum instance into [`ItemToAdd`](crate::types::RelatedItemsUpdate::ItemToAdd), extracting the inner [`RelatedItem`](crate::types::RelatedItem).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_item_to_add(&self) -> ::std::result::Result<&crate::types::RelatedItem, &Self> {
        if let RelatedItemsUpdate::ItemToAdd(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ItemToAdd`](crate::types::RelatedItemsUpdate::ItemToAdd).
    pub fn is_item_to_add(&self) -> bool {
        self.as_item_to_add().is_ok()
    }
    /// Tries to convert the enum instance into [`ItemToRemove`](crate::types::RelatedItemsUpdate::ItemToRemove), extracting the inner [`ItemIdentifier`](crate::types::ItemIdentifier).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_item_to_remove(&self) -> ::std::result::Result<&crate::types::ItemIdentifier, &Self> {
        if let RelatedItemsUpdate::ItemToRemove(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ItemToRemove`](crate::types::RelatedItemsUpdate::ItemToRemove).
    pub fn is_item_to_remove(&self) -> bool {
        self.as_item_to_remove().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
