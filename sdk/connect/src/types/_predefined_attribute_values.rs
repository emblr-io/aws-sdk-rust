// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about values of a predefined attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum PredefinedAttributeValues {
    /// <p>Predefined attribute values of type string list.</p>
    StringList(::std::vec::Vec<::std::string::String>),
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
impl PredefinedAttributeValues {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`StringList`](crate::types::PredefinedAttributeValues::StringList), extracting the inner [`Vec`](::std::vec::Vec).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_list(&self) -> ::std::result::Result<&::std::vec::Vec<::std::string::String>, &Self> {
        if let PredefinedAttributeValues::StringList(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringList`](crate::types::PredefinedAttributeValues::StringList).
    pub fn is_string_list(&self) -> bool {
        self.as_string_list().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
