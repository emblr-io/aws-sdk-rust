// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ReadSetExportJobItemStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let readsetexportjobitemstatus = unimplemented!();
/// match readsetexportjobitemstatus {
///     ReadSetExportJobItemStatus::Failed => { /* ... */ },
///     ReadSetExportJobItemStatus::Finished => { /* ... */ },
///     ReadSetExportJobItemStatus::InProgress => { /* ... */ },
///     ReadSetExportJobItemStatus::NotStarted => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `readsetexportjobitemstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ReadSetExportJobItemStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ReadSetExportJobItemStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ReadSetExportJobItemStatus::NewFeature` is defined.
/// Specifically, when `readsetexportjobitemstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ReadSetExportJobItemStatus::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum ReadSetExportJobItemStatus {
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    Finished,
    #[allow(missing_docs)] // documentation missing in model
    InProgress,
    #[allow(missing_docs)] // documentation missing in model
    NotStarted,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ReadSetExportJobItemStatus {
    fn from(s: &str) -> Self {
        match s {
            "FAILED" => ReadSetExportJobItemStatus::Failed,
            "FINISHED" => ReadSetExportJobItemStatus::Finished,
            "IN_PROGRESS" => ReadSetExportJobItemStatus::InProgress,
            "NOT_STARTED" => ReadSetExportJobItemStatus::NotStarted,
            other => ReadSetExportJobItemStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ReadSetExportJobItemStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ReadSetExportJobItemStatus::from(s))
    }
}
impl ReadSetExportJobItemStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ReadSetExportJobItemStatus::Failed => "FAILED",
            ReadSetExportJobItemStatus::Finished => "FINISHED",
            ReadSetExportJobItemStatus::InProgress => "IN_PROGRESS",
            ReadSetExportJobItemStatus::NotStarted => "NOT_STARTED",
            ReadSetExportJobItemStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["FAILED", "FINISHED", "IN_PROGRESS", "NOT_STARTED"]
    }
}
impl ::std::convert::AsRef<str> for ReadSetExportJobItemStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ReadSetExportJobItemStatus {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for ReadSetExportJobItemStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReadSetExportJobItemStatus::Failed => write!(f, "FAILED"),
            ReadSetExportJobItemStatus::Finished => write!(f, "FINISHED"),
            ReadSetExportJobItemStatus::InProgress => write!(f, "IN_PROGRESS"),
            ReadSetExportJobItemStatus::NotStarted => write!(f, "NOT_STARTED"),
            ReadSetExportJobItemStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
