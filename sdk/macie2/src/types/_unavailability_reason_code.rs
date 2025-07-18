// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `UnavailabilityReasonCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let unavailabilityreasoncode = unimplemented!();
/// match unavailabilityreasoncode {
///     UnavailabilityReasonCode::AccountNotInOrganization => { /* ... */ },
///     UnavailabilityReasonCode::InvalidClassificationResult => { /* ... */ },
///     UnavailabilityReasonCode::InvalidResultSignature => { /* ... */ },
///     UnavailabilityReasonCode::MemberRoleTooPermissive => { /* ... */ },
///     UnavailabilityReasonCode::MissingGetMemberPermission => { /* ... */ },
///     UnavailabilityReasonCode::ObjectExceedsSizeQuota => { /* ... */ },
///     UnavailabilityReasonCode::ObjectUnavailable => { /* ... */ },
///     UnavailabilityReasonCode::ResultNotSigned => { /* ... */ },
///     UnavailabilityReasonCode::RoleTooPermissive => { /* ... */ },
///     UnavailabilityReasonCode::UnsupportedFindingType => { /* ... */ },
///     UnavailabilityReasonCode::UnsupportedObjectType => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `unavailabilityreasoncode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `UnavailabilityReasonCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `UnavailabilityReasonCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `UnavailabilityReasonCode::NewFeature` is defined.
/// Specifically, when `unavailabilityreasoncode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `UnavailabilityReasonCode::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>Specifies why occurrences of sensitive data can't be retrieved for a finding. Possible values are:</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum UnavailabilityReasonCode {
    #[allow(missing_docs)] // documentation missing in model
    AccountNotInOrganization,
    #[allow(missing_docs)] // documentation missing in model
    InvalidClassificationResult,
    #[allow(missing_docs)] // documentation missing in model
    InvalidResultSignature,
    #[allow(missing_docs)] // documentation missing in model
    MemberRoleTooPermissive,
    #[allow(missing_docs)] // documentation missing in model
    MissingGetMemberPermission,
    #[allow(missing_docs)] // documentation missing in model
    ObjectExceedsSizeQuota,
    #[allow(missing_docs)] // documentation missing in model
    ObjectUnavailable,
    #[allow(missing_docs)] // documentation missing in model
    ResultNotSigned,
    #[allow(missing_docs)] // documentation missing in model
    RoleTooPermissive,
    #[allow(missing_docs)] // documentation missing in model
    UnsupportedFindingType,
    #[allow(missing_docs)] // documentation missing in model
    UnsupportedObjectType,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for UnavailabilityReasonCode {
    fn from(s: &str) -> Self {
        match s {
            "ACCOUNT_NOT_IN_ORGANIZATION" => UnavailabilityReasonCode::AccountNotInOrganization,
            "INVALID_CLASSIFICATION_RESULT" => UnavailabilityReasonCode::InvalidClassificationResult,
            "INVALID_RESULT_SIGNATURE" => UnavailabilityReasonCode::InvalidResultSignature,
            "MEMBER_ROLE_TOO_PERMISSIVE" => UnavailabilityReasonCode::MemberRoleTooPermissive,
            "MISSING_GET_MEMBER_PERMISSION" => UnavailabilityReasonCode::MissingGetMemberPermission,
            "OBJECT_EXCEEDS_SIZE_QUOTA" => UnavailabilityReasonCode::ObjectExceedsSizeQuota,
            "OBJECT_UNAVAILABLE" => UnavailabilityReasonCode::ObjectUnavailable,
            "RESULT_NOT_SIGNED" => UnavailabilityReasonCode::ResultNotSigned,
            "ROLE_TOO_PERMISSIVE" => UnavailabilityReasonCode::RoleTooPermissive,
            "UNSUPPORTED_FINDING_TYPE" => UnavailabilityReasonCode::UnsupportedFindingType,
            "UNSUPPORTED_OBJECT_TYPE" => UnavailabilityReasonCode::UnsupportedObjectType,
            other => UnavailabilityReasonCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for UnavailabilityReasonCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(UnavailabilityReasonCode::from(s))
    }
}
impl UnavailabilityReasonCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            UnavailabilityReasonCode::AccountNotInOrganization => "ACCOUNT_NOT_IN_ORGANIZATION",
            UnavailabilityReasonCode::InvalidClassificationResult => "INVALID_CLASSIFICATION_RESULT",
            UnavailabilityReasonCode::InvalidResultSignature => "INVALID_RESULT_SIGNATURE",
            UnavailabilityReasonCode::MemberRoleTooPermissive => "MEMBER_ROLE_TOO_PERMISSIVE",
            UnavailabilityReasonCode::MissingGetMemberPermission => "MISSING_GET_MEMBER_PERMISSION",
            UnavailabilityReasonCode::ObjectExceedsSizeQuota => "OBJECT_EXCEEDS_SIZE_QUOTA",
            UnavailabilityReasonCode::ObjectUnavailable => "OBJECT_UNAVAILABLE",
            UnavailabilityReasonCode::ResultNotSigned => "RESULT_NOT_SIGNED",
            UnavailabilityReasonCode::RoleTooPermissive => "ROLE_TOO_PERMISSIVE",
            UnavailabilityReasonCode::UnsupportedFindingType => "UNSUPPORTED_FINDING_TYPE",
            UnavailabilityReasonCode::UnsupportedObjectType => "UNSUPPORTED_OBJECT_TYPE",
            UnavailabilityReasonCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACCOUNT_NOT_IN_ORGANIZATION",
            "INVALID_CLASSIFICATION_RESULT",
            "INVALID_RESULT_SIGNATURE",
            "MEMBER_ROLE_TOO_PERMISSIVE",
            "MISSING_GET_MEMBER_PERMISSION",
            "OBJECT_EXCEEDS_SIZE_QUOTA",
            "OBJECT_UNAVAILABLE",
            "RESULT_NOT_SIGNED",
            "ROLE_TOO_PERMISSIVE",
            "UNSUPPORTED_FINDING_TYPE",
            "UNSUPPORTED_OBJECT_TYPE",
        ]
    }
}
impl ::std::convert::AsRef<str> for UnavailabilityReasonCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl UnavailabilityReasonCode {
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
impl ::std::fmt::Display for UnavailabilityReasonCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            UnavailabilityReasonCode::AccountNotInOrganization => write!(f, "ACCOUNT_NOT_IN_ORGANIZATION"),
            UnavailabilityReasonCode::InvalidClassificationResult => write!(f, "INVALID_CLASSIFICATION_RESULT"),
            UnavailabilityReasonCode::InvalidResultSignature => write!(f, "INVALID_RESULT_SIGNATURE"),
            UnavailabilityReasonCode::MemberRoleTooPermissive => write!(f, "MEMBER_ROLE_TOO_PERMISSIVE"),
            UnavailabilityReasonCode::MissingGetMemberPermission => write!(f, "MISSING_GET_MEMBER_PERMISSION"),
            UnavailabilityReasonCode::ObjectExceedsSizeQuota => write!(f, "OBJECT_EXCEEDS_SIZE_QUOTA"),
            UnavailabilityReasonCode::ObjectUnavailable => write!(f, "OBJECT_UNAVAILABLE"),
            UnavailabilityReasonCode::ResultNotSigned => write!(f, "RESULT_NOT_SIGNED"),
            UnavailabilityReasonCode::RoleTooPermissive => write!(f, "ROLE_TOO_PERMISSIVE"),
            UnavailabilityReasonCode::UnsupportedFindingType => write!(f, "UNSUPPORTED_FINDING_TYPE"),
            UnavailabilityReasonCode::UnsupportedObjectType => write!(f, "UNSUPPORTED_OBJECT_TYPE"),
            UnavailabilityReasonCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
