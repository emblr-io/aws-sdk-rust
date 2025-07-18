// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CannedAclForObjectsValue`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let cannedaclforobjectsvalue = unimplemented!();
/// match cannedaclforobjectsvalue {
///     CannedAclForObjectsValue::AuthenticatedRead => { /* ... */ },
///     CannedAclForObjectsValue::AwsExecRead => { /* ... */ },
///     CannedAclForObjectsValue::BucketOwnerFullControl => { /* ... */ },
///     CannedAclForObjectsValue::BucketOwnerRead => { /* ... */ },
///     CannedAclForObjectsValue::None => { /* ... */ },
///     CannedAclForObjectsValue::Private => { /* ... */ },
///     CannedAclForObjectsValue::PublicRead => { /* ... */ },
///     CannedAclForObjectsValue::PublicReadWrite => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `cannedaclforobjectsvalue` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CannedAclForObjectsValue::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CannedAclForObjectsValue::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CannedAclForObjectsValue::NewFeature` is defined.
/// Specifically, when `cannedaclforobjectsvalue` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CannedAclForObjectsValue::NewFeature` also yielding `"NewFeature"`.
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
pub enum CannedAclForObjectsValue {
    #[allow(missing_docs)] // documentation missing in model
    AuthenticatedRead,
    #[allow(missing_docs)] // documentation missing in model
    AwsExecRead,
    #[allow(missing_docs)] // documentation missing in model
    BucketOwnerFullControl,
    #[allow(missing_docs)] // documentation missing in model
    BucketOwnerRead,
    #[allow(missing_docs)] // documentation missing in model
    None,
    #[allow(missing_docs)] // documentation missing in model
    Private,
    #[allow(missing_docs)] // documentation missing in model
    PublicRead,
    #[allow(missing_docs)] // documentation missing in model
    PublicReadWrite,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CannedAclForObjectsValue {
    fn from(s: &str) -> Self {
        match s {
            "authenticated-read" => CannedAclForObjectsValue::AuthenticatedRead,
            "aws-exec-read" => CannedAclForObjectsValue::AwsExecRead,
            "bucket-owner-full-control" => CannedAclForObjectsValue::BucketOwnerFullControl,
            "bucket-owner-read" => CannedAclForObjectsValue::BucketOwnerRead,
            "none" => CannedAclForObjectsValue::None,
            "private" => CannedAclForObjectsValue::Private,
            "public-read" => CannedAclForObjectsValue::PublicRead,
            "public-read-write" => CannedAclForObjectsValue::PublicReadWrite,
            other => CannedAclForObjectsValue::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CannedAclForObjectsValue {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CannedAclForObjectsValue::from(s))
    }
}
impl CannedAclForObjectsValue {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CannedAclForObjectsValue::AuthenticatedRead => "authenticated-read",
            CannedAclForObjectsValue::AwsExecRead => "aws-exec-read",
            CannedAclForObjectsValue::BucketOwnerFullControl => "bucket-owner-full-control",
            CannedAclForObjectsValue::BucketOwnerRead => "bucket-owner-read",
            CannedAclForObjectsValue::None => "none",
            CannedAclForObjectsValue::Private => "private",
            CannedAclForObjectsValue::PublicRead => "public-read",
            CannedAclForObjectsValue::PublicReadWrite => "public-read-write",
            CannedAclForObjectsValue::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "authenticated-read",
            "aws-exec-read",
            "bucket-owner-full-control",
            "bucket-owner-read",
            "none",
            "private",
            "public-read",
            "public-read-write",
        ]
    }
}
impl ::std::convert::AsRef<str> for CannedAclForObjectsValue {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CannedAclForObjectsValue {
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
impl ::std::fmt::Display for CannedAclForObjectsValue {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CannedAclForObjectsValue::AuthenticatedRead => write!(f, "authenticated-read"),
            CannedAclForObjectsValue::AwsExecRead => write!(f, "aws-exec-read"),
            CannedAclForObjectsValue::BucketOwnerFullControl => write!(f, "bucket-owner-full-control"),
            CannedAclForObjectsValue::BucketOwnerRead => write!(f, "bucket-owner-read"),
            CannedAclForObjectsValue::None => write!(f, "none"),
            CannedAclForObjectsValue::Private => write!(f, "private"),
            CannedAclForObjectsValue::PublicRead => write!(f, "public-read"),
            CannedAclForObjectsValue::PublicReadWrite => write!(f, "public-read-write"),
            CannedAclForObjectsValue::Unknown(value) => write!(f, "{}", value),
        }
    }
}
