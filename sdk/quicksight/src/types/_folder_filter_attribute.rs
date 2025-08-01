// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `FolderFilterAttribute`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let folderfilterattribute = unimplemented!();
/// match folderfilterattribute {
///     FolderFilterAttribute::DirectQuicksightOwner => { /* ... */ },
///     FolderFilterAttribute::DirectQuicksightSoleOwner => { /* ... */ },
///     FolderFilterAttribute::DirectQuicksightViewerOrOwner => { /* ... */ },
///     FolderFilterAttribute::FolderName => { /* ... */ },
///     FolderFilterAttribute::ParentFolderArn => { /* ... */ },
///     FolderFilterAttribute::QuicksightOwner => { /* ... */ },
///     FolderFilterAttribute::QuicksightViewerOrOwner => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `folderfilterattribute` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `FolderFilterAttribute::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `FolderFilterAttribute::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `FolderFilterAttribute::NewFeature` is defined.
/// Specifically, when `folderfilterattribute` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `FolderFilterAttribute::NewFeature` also yielding `"NewFeature"`.
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
pub enum FolderFilterAttribute {
    #[allow(missing_docs)] // documentation missing in model
    DirectQuicksightOwner,
    #[allow(missing_docs)] // documentation missing in model
    DirectQuicksightSoleOwner,
    #[allow(missing_docs)] // documentation missing in model
    DirectQuicksightViewerOrOwner,
    #[allow(missing_docs)] // documentation missing in model
    FolderName,
    #[allow(missing_docs)] // documentation missing in model
    ParentFolderArn,
    #[allow(missing_docs)] // documentation missing in model
    QuicksightOwner,
    #[allow(missing_docs)] // documentation missing in model
    QuicksightViewerOrOwner,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for FolderFilterAttribute {
    fn from(s: &str) -> Self {
        match s {
            "DIRECT_QUICKSIGHT_OWNER" => FolderFilterAttribute::DirectQuicksightOwner,
            "DIRECT_QUICKSIGHT_SOLE_OWNER" => FolderFilterAttribute::DirectQuicksightSoleOwner,
            "DIRECT_QUICKSIGHT_VIEWER_OR_OWNER" => FolderFilterAttribute::DirectQuicksightViewerOrOwner,
            "FOLDER_NAME" => FolderFilterAttribute::FolderName,
            "PARENT_FOLDER_ARN" => FolderFilterAttribute::ParentFolderArn,
            "QUICKSIGHT_OWNER" => FolderFilterAttribute::QuicksightOwner,
            "QUICKSIGHT_VIEWER_OR_OWNER" => FolderFilterAttribute::QuicksightViewerOrOwner,
            other => FolderFilterAttribute::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for FolderFilterAttribute {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(FolderFilterAttribute::from(s))
    }
}
impl FolderFilterAttribute {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            FolderFilterAttribute::DirectQuicksightOwner => "DIRECT_QUICKSIGHT_OWNER",
            FolderFilterAttribute::DirectQuicksightSoleOwner => "DIRECT_QUICKSIGHT_SOLE_OWNER",
            FolderFilterAttribute::DirectQuicksightViewerOrOwner => "DIRECT_QUICKSIGHT_VIEWER_OR_OWNER",
            FolderFilterAttribute::FolderName => "FOLDER_NAME",
            FolderFilterAttribute::ParentFolderArn => "PARENT_FOLDER_ARN",
            FolderFilterAttribute::QuicksightOwner => "QUICKSIGHT_OWNER",
            FolderFilterAttribute::QuicksightViewerOrOwner => "QUICKSIGHT_VIEWER_OR_OWNER",
            FolderFilterAttribute::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DIRECT_QUICKSIGHT_OWNER",
            "DIRECT_QUICKSIGHT_SOLE_OWNER",
            "DIRECT_QUICKSIGHT_VIEWER_OR_OWNER",
            "FOLDER_NAME",
            "PARENT_FOLDER_ARN",
            "QUICKSIGHT_OWNER",
            "QUICKSIGHT_VIEWER_OR_OWNER",
        ]
    }
}
impl ::std::convert::AsRef<str> for FolderFilterAttribute {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FolderFilterAttribute {
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
impl ::std::fmt::Display for FolderFilterAttribute {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FolderFilterAttribute::DirectQuicksightOwner => write!(f, "DIRECT_QUICKSIGHT_OWNER"),
            FolderFilterAttribute::DirectQuicksightSoleOwner => write!(f, "DIRECT_QUICKSIGHT_SOLE_OWNER"),
            FolderFilterAttribute::DirectQuicksightViewerOrOwner => write!(f, "DIRECT_QUICKSIGHT_VIEWER_OR_OWNER"),
            FolderFilterAttribute::FolderName => write!(f, "FOLDER_NAME"),
            FolderFilterAttribute::ParentFolderArn => write!(f, "PARENT_FOLDER_ARN"),
            FolderFilterAttribute::QuicksightOwner => write!(f, "QUICKSIGHT_OWNER"),
            FolderFilterAttribute::QuicksightViewerOrOwner => write!(f, "QUICKSIGHT_VIEWER_OR_OWNER"),
            FolderFilterAttribute::Unknown(value) => write!(f, "{}", value),
        }
    }
}
