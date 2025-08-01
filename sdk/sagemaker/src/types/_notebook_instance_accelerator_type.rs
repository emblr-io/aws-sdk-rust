// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `NotebookInstanceAcceleratorType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let notebookinstanceacceleratortype = unimplemented!();
/// match notebookinstanceacceleratortype {
///     NotebookInstanceAcceleratorType::MlEia1Large => { /* ... */ },
///     NotebookInstanceAcceleratorType::MlEia1Medium => { /* ... */ },
///     NotebookInstanceAcceleratorType::MlEia1Xlarge => { /* ... */ },
///     NotebookInstanceAcceleratorType::MlEia2Large => { /* ... */ },
///     NotebookInstanceAcceleratorType::MlEia2Medium => { /* ... */ },
///     NotebookInstanceAcceleratorType::MlEia2Xlarge => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `notebookinstanceacceleratortype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `NotebookInstanceAcceleratorType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `NotebookInstanceAcceleratorType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `NotebookInstanceAcceleratorType::NewFeature` is defined.
/// Specifically, when `notebookinstanceacceleratortype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `NotebookInstanceAcceleratorType::NewFeature` also yielding `"NewFeature"`.
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
pub enum NotebookInstanceAcceleratorType {
    #[allow(missing_docs)] // documentation missing in model
    MlEia1Large,
    #[allow(missing_docs)] // documentation missing in model
    MlEia1Medium,
    #[allow(missing_docs)] // documentation missing in model
    MlEia1Xlarge,
    #[allow(missing_docs)] // documentation missing in model
    MlEia2Large,
    #[allow(missing_docs)] // documentation missing in model
    MlEia2Medium,
    #[allow(missing_docs)] // documentation missing in model
    MlEia2Xlarge,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for NotebookInstanceAcceleratorType {
    fn from(s: &str) -> Self {
        match s {
            "ml.eia1.large" => NotebookInstanceAcceleratorType::MlEia1Large,
            "ml.eia1.medium" => NotebookInstanceAcceleratorType::MlEia1Medium,
            "ml.eia1.xlarge" => NotebookInstanceAcceleratorType::MlEia1Xlarge,
            "ml.eia2.large" => NotebookInstanceAcceleratorType::MlEia2Large,
            "ml.eia2.medium" => NotebookInstanceAcceleratorType::MlEia2Medium,
            "ml.eia2.xlarge" => NotebookInstanceAcceleratorType::MlEia2Xlarge,
            other => NotebookInstanceAcceleratorType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for NotebookInstanceAcceleratorType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(NotebookInstanceAcceleratorType::from(s))
    }
}
impl NotebookInstanceAcceleratorType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            NotebookInstanceAcceleratorType::MlEia1Large => "ml.eia1.large",
            NotebookInstanceAcceleratorType::MlEia1Medium => "ml.eia1.medium",
            NotebookInstanceAcceleratorType::MlEia1Xlarge => "ml.eia1.xlarge",
            NotebookInstanceAcceleratorType::MlEia2Large => "ml.eia2.large",
            NotebookInstanceAcceleratorType::MlEia2Medium => "ml.eia2.medium",
            NotebookInstanceAcceleratorType::MlEia2Xlarge => "ml.eia2.xlarge",
            NotebookInstanceAcceleratorType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ml.eia1.large",
            "ml.eia1.medium",
            "ml.eia1.xlarge",
            "ml.eia2.large",
            "ml.eia2.medium",
            "ml.eia2.xlarge",
        ]
    }
}
impl ::std::convert::AsRef<str> for NotebookInstanceAcceleratorType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl NotebookInstanceAcceleratorType {
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
impl ::std::fmt::Display for NotebookInstanceAcceleratorType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NotebookInstanceAcceleratorType::MlEia1Large => write!(f, "ml.eia1.large"),
            NotebookInstanceAcceleratorType::MlEia1Medium => write!(f, "ml.eia1.medium"),
            NotebookInstanceAcceleratorType::MlEia1Xlarge => write!(f, "ml.eia1.xlarge"),
            NotebookInstanceAcceleratorType::MlEia2Large => write!(f, "ml.eia2.large"),
            NotebookInstanceAcceleratorType::MlEia2Medium => write!(f, "ml.eia2.medium"),
            NotebookInstanceAcceleratorType::MlEia2Xlarge => write!(f, "ml.eia2.xlarge"),
            NotebookInstanceAcceleratorType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
