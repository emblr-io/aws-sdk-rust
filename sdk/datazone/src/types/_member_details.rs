// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details about a project member.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum MemberDetails {
    /// <p>The group details of a project member.</p>
    Group(crate::types::GroupDetails),
    /// <p>The user details of a project member.</p>
    User(crate::types::UserDetails),
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
impl MemberDetails {
    /// Tries to convert the enum instance into [`Group`](crate::types::MemberDetails::Group), extracting the inner [`GroupDetails`](crate::types::GroupDetails).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_group(&self) -> ::std::result::Result<&crate::types::GroupDetails, &Self> {
        if let MemberDetails::Group(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Group`](crate::types::MemberDetails::Group).
    pub fn is_group(&self) -> bool {
        self.as_group().is_ok()
    }
    /// Tries to convert the enum instance into [`User`](crate::types::MemberDetails::User), extracting the inner [`UserDetails`](crate::types::UserDetails).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_user(&self) -> ::std::result::Result<&crate::types::UserDetails, &Self> {
        if let MemberDetails::User(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`User`](crate::types::MemberDetails::User).
    pub fn is_user(&self) -> bool {
        self.as_user().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
