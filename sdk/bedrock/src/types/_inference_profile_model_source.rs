// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the model or system-defined inference profile that is the source for an inference profile..</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum InferenceProfileModelSource {
    /// <p>The ARN of the model or system-defined inference profile that is the source for the inference profile.</p>
    CopyFrom(::std::string::String),
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
impl InferenceProfileModelSource {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`CopyFrom`](crate::types::InferenceProfileModelSource::CopyFrom), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_copy_from(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let InferenceProfileModelSource::CopyFrom(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CopyFrom`](crate::types::InferenceProfileModelSource::CopyFrom).
    pub fn is_copy_from(&self) -> bool {
        self.as_copy_from().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
