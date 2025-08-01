// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `BatchReadExceptionType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let batchreadexceptiontype = unimplemented!();
/// match batchreadexceptiontype {
///     BatchReadExceptionType::AccessDeniedException => { /* ... */ },
///     BatchReadExceptionType::CannotListParentOfRootException => { /* ... */ },
///     BatchReadExceptionType::DirectoryNotEnabledException => { /* ... */ },
///     BatchReadExceptionType::FacetValidationException => { /* ... */ },
///     BatchReadExceptionType::InternalServiceException => { /* ... */ },
///     BatchReadExceptionType::InvalidArnException => { /* ... */ },
///     BatchReadExceptionType::InvalidNextTokenException => { /* ... */ },
///     BatchReadExceptionType::LimitExceededException => { /* ... */ },
///     BatchReadExceptionType::NotIndexException => { /* ... */ },
///     BatchReadExceptionType::NotNodeException => { /* ... */ },
///     BatchReadExceptionType::NotPolicyException => { /* ... */ },
///     BatchReadExceptionType::ResourceNotFoundException => { /* ... */ },
///     BatchReadExceptionType::ValidationException => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `batchreadexceptiontype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `BatchReadExceptionType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `BatchReadExceptionType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `BatchReadExceptionType::NewFeature` is defined.
/// Specifically, when `batchreadexceptiontype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `BatchReadExceptionType::NewFeature` also yielding `"NewFeature"`.
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
pub enum BatchReadExceptionType {
    #[allow(missing_docs)] // documentation missing in model
    AccessDeniedException,
    #[allow(missing_docs)] // documentation missing in model
    CannotListParentOfRootException,
    #[allow(missing_docs)] // documentation missing in model
    DirectoryNotEnabledException,
    #[allow(missing_docs)] // documentation missing in model
    FacetValidationException,
    #[allow(missing_docs)] // documentation missing in model
    InternalServiceException,
    #[allow(missing_docs)] // documentation missing in model
    InvalidArnException,
    #[allow(missing_docs)] // documentation missing in model
    InvalidNextTokenException,
    #[allow(missing_docs)] // documentation missing in model
    LimitExceededException,
    #[allow(missing_docs)] // documentation missing in model
    NotIndexException,
    #[allow(missing_docs)] // documentation missing in model
    NotNodeException,
    #[allow(missing_docs)] // documentation missing in model
    NotPolicyException,
    #[allow(missing_docs)] // documentation missing in model
    ResourceNotFoundException,
    #[allow(missing_docs)] // documentation missing in model
    ValidationException,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for BatchReadExceptionType {
    fn from(s: &str) -> Self {
        match s {
            "AccessDeniedException" => BatchReadExceptionType::AccessDeniedException,
            "CannotListParentOfRootException" => BatchReadExceptionType::CannotListParentOfRootException,
            "DirectoryNotEnabledException" => BatchReadExceptionType::DirectoryNotEnabledException,
            "FacetValidationException" => BatchReadExceptionType::FacetValidationException,
            "InternalServiceException" => BatchReadExceptionType::InternalServiceException,
            "InvalidArnException" => BatchReadExceptionType::InvalidArnException,
            "InvalidNextTokenException" => BatchReadExceptionType::InvalidNextTokenException,
            "LimitExceededException" => BatchReadExceptionType::LimitExceededException,
            "NotIndexException" => BatchReadExceptionType::NotIndexException,
            "NotNodeException" => BatchReadExceptionType::NotNodeException,
            "NotPolicyException" => BatchReadExceptionType::NotPolicyException,
            "ResourceNotFoundException" => BatchReadExceptionType::ResourceNotFoundException,
            "ValidationException" => BatchReadExceptionType::ValidationException,
            other => BatchReadExceptionType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for BatchReadExceptionType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(BatchReadExceptionType::from(s))
    }
}
impl BatchReadExceptionType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            BatchReadExceptionType::AccessDeniedException => "AccessDeniedException",
            BatchReadExceptionType::CannotListParentOfRootException => "CannotListParentOfRootException",
            BatchReadExceptionType::DirectoryNotEnabledException => "DirectoryNotEnabledException",
            BatchReadExceptionType::FacetValidationException => "FacetValidationException",
            BatchReadExceptionType::InternalServiceException => "InternalServiceException",
            BatchReadExceptionType::InvalidArnException => "InvalidArnException",
            BatchReadExceptionType::InvalidNextTokenException => "InvalidNextTokenException",
            BatchReadExceptionType::LimitExceededException => "LimitExceededException",
            BatchReadExceptionType::NotIndexException => "NotIndexException",
            BatchReadExceptionType::NotNodeException => "NotNodeException",
            BatchReadExceptionType::NotPolicyException => "NotPolicyException",
            BatchReadExceptionType::ResourceNotFoundException => "ResourceNotFoundException",
            BatchReadExceptionType::ValidationException => "ValidationException",
            BatchReadExceptionType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AccessDeniedException",
            "CannotListParentOfRootException",
            "DirectoryNotEnabledException",
            "FacetValidationException",
            "InternalServiceException",
            "InvalidArnException",
            "InvalidNextTokenException",
            "LimitExceededException",
            "NotIndexException",
            "NotNodeException",
            "NotPolicyException",
            "ResourceNotFoundException",
            "ValidationException",
        ]
    }
}
impl ::std::convert::AsRef<str> for BatchReadExceptionType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl BatchReadExceptionType {
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
impl ::std::fmt::Display for BatchReadExceptionType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            BatchReadExceptionType::AccessDeniedException => write!(f, "AccessDeniedException"),
            BatchReadExceptionType::CannotListParentOfRootException => write!(f, "CannotListParentOfRootException"),
            BatchReadExceptionType::DirectoryNotEnabledException => write!(f, "DirectoryNotEnabledException"),
            BatchReadExceptionType::FacetValidationException => write!(f, "FacetValidationException"),
            BatchReadExceptionType::InternalServiceException => write!(f, "InternalServiceException"),
            BatchReadExceptionType::InvalidArnException => write!(f, "InvalidArnException"),
            BatchReadExceptionType::InvalidNextTokenException => write!(f, "InvalidNextTokenException"),
            BatchReadExceptionType::LimitExceededException => write!(f, "LimitExceededException"),
            BatchReadExceptionType::NotIndexException => write!(f, "NotIndexException"),
            BatchReadExceptionType::NotNodeException => write!(f, "NotNodeException"),
            BatchReadExceptionType::NotPolicyException => write!(f, "NotPolicyException"),
            BatchReadExceptionType::ResourceNotFoundException => write!(f, "ResourceNotFoundException"),
            BatchReadExceptionType::ValidationException => write!(f, "ValidationException"),
            BatchReadExceptionType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
