// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Source of the campaign
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Source {
    /// Amazon Resource Names(ARN)
    CustomerProfilesSegmentArn(::std::string::String),
    /// Event trigger of the campaign
    EventTrigger(crate::types::EventTrigger),
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
impl Source {
    /// Tries to convert the enum instance into [`CustomerProfilesSegmentArn`](crate::types::Source::CustomerProfilesSegmentArn), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_customer_profiles_segment_arn(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let Source::CustomerProfilesSegmentArn(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CustomerProfilesSegmentArn`](crate::types::Source::CustomerProfilesSegmentArn).
    pub fn is_customer_profiles_segment_arn(&self) -> bool {
        self.as_customer_profiles_segment_arn().is_ok()
    }
    /// Tries to convert the enum instance into [`EventTrigger`](crate::types::Source::EventTrigger), extracting the inner [`EventTrigger`](crate::types::EventTrigger).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_event_trigger(&self) -> ::std::result::Result<&crate::types::EventTrigger, &Self> {
        if let Source::EventTrigger(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`EventTrigger`](crate::types::Source::EventTrigger).
    pub fn is_event_trigger(&self) -> bool {
        self.as_event_trigger().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
