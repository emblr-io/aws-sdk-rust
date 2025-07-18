// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This represents a sections within a panel or tab of the page layout.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Section {
    /// <p>Consists of a group of fields and associated properties.</p>
    FieldGroup(crate::types::FieldGroup),
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
impl Section {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`FieldGroup`](crate::types::Section::FieldGroup), extracting the inner [`FieldGroup`](crate::types::FieldGroup).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_field_group(&self) -> ::std::result::Result<&crate::types::FieldGroup, &Self> {
        if let Section::FieldGroup(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FieldGroup`](crate::types::Section::FieldGroup).
    pub fn is_field_group(&self) -> bool {
        self.as_field_group().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
