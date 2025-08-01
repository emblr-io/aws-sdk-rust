// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ScalarFunctions`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let scalarfunctions = unimplemented!();
/// match scalarfunctions {
///     ScalarFunctions::Abs => { /* ... */ },
///     ScalarFunctions::Cast => { /* ... */ },
///     ScalarFunctions::Ceiling => { /* ... */ },
///     ScalarFunctions::Coalesce => { /* ... */ },
///     ScalarFunctions::Convert => { /* ... */ },
///     ScalarFunctions::CurrentDate => { /* ... */ },
///     ScalarFunctions::Dateadd => { /* ... */ },
///     ScalarFunctions::Extract => { /* ... */ },
///     ScalarFunctions::Floor => { /* ... */ },
///     ScalarFunctions::Getdate => { /* ... */ },
///     ScalarFunctions::Ln => { /* ... */ },
///     ScalarFunctions::Log => { /* ... */ },
///     ScalarFunctions::Lower => { /* ... */ },
///     ScalarFunctions::Round => { /* ... */ },
///     ScalarFunctions::Rtrim => { /* ... */ },
///     ScalarFunctions::Sqrt => { /* ... */ },
///     ScalarFunctions::Substring => { /* ... */ },
///     ScalarFunctions::ToChar => { /* ... */ },
///     ScalarFunctions::ToDate => { /* ... */ },
///     ScalarFunctions::ToNumber => { /* ... */ },
///     ScalarFunctions::ToTimestamp => { /* ... */ },
///     ScalarFunctions::Trim => { /* ... */ },
///     ScalarFunctions::Trunc => { /* ... */ },
///     ScalarFunctions::Upper => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `scalarfunctions` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ScalarFunctions::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ScalarFunctions::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ScalarFunctions::NewFeature` is defined.
/// Specifically, when `scalarfunctions` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ScalarFunctions::NewFeature` also yielding `"NewFeature"`.
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
pub enum ScalarFunctions {
    #[allow(missing_docs)] // documentation missing in model
    Abs,
    #[allow(missing_docs)] // documentation missing in model
    Cast,
    #[allow(missing_docs)] // documentation missing in model
    Ceiling,
    #[allow(missing_docs)] // documentation missing in model
    Coalesce,
    #[allow(missing_docs)] // documentation missing in model
    Convert,
    #[allow(missing_docs)] // documentation missing in model
    CurrentDate,
    #[allow(missing_docs)] // documentation missing in model
    Dateadd,
    #[allow(missing_docs)] // documentation missing in model
    Extract,
    #[allow(missing_docs)] // documentation missing in model
    Floor,
    #[allow(missing_docs)] // documentation missing in model
    Getdate,
    #[allow(missing_docs)] // documentation missing in model
    Ln,
    #[allow(missing_docs)] // documentation missing in model
    Log,
    #[allow(missing_docs)] // documentation missing in model
    Lower,
    #[allow(missing_docs)] // documentation missing in model
    Round,
    #[allow(missing_docs)] // documentation missing in model
    Rtrim,
    #[allow(missing_docs)] // documentation missing in model
    Sqrt,
    #[allow(missing_docs)] // documentation missing in model
    Substring,
    #[allow(missing_docs)] // documentation missing in model
    ToChar,
    #[allow(missing_docs)] // documentation missing in model
    ToDate,
    #[allow(missing_docs)] // documentation missing in model
    ToNumber,
    #[allow(missing_docs)] // documentation missing in model
    ToTimestamp,
    #[allow(missing_docs)] // documentation missing in model
    Trim,
    #[allow(missing_docs)] // documentation missing in model
    Trunc,
    #[allow(missing_docs)] // documentation missing in model
    Upper,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ScalarFunctions {
    fn from(s: &str) -> Self {
        match s {
            "ABS" => ScalarFunctions::Abs,
            "CAST" => ScalarFunctions::Cast,
            "CEILING" => ScalarFunctions::Ceiling,
            "COALESCE" => ScalarFunctions::Coalesce,
            "CONVERT" => ScalarFunctions::Convert,
            "CURRENT_DATE" => ScalarFunctions::CurrentDate,
            "DATEADD" => ScalarFunctions::Dateadd,
            "EXTRACT" => ScalarFunctions::Extract,
            "FLOOR" => ScalarFunctions::Floor,
            "GETDATE" => ScalarFunctions::Getdate,
            "LN" => ScalarFunctions::Ln,
            "LOG" => ScalarFunctions::Log,
            "LOWER" => ScalarFunctions::Lower,
            "ROUND" => ScalarFunctions::Round,
            "RTRIM" => ScalarFunctions::Rtrim,
            "SQRT" => ScalarFunctions::Sqrt,
            "SUBSTRING" => ScalarFunctions::Substring,
            "TO_CHAR" => ScalarFunctions::ToChar,
            "TO_DATE" => ScalarFunctions::ToDate,
            "TO_NUMBER" => ScalarFunctions::ToNumber,
            "TO_TIMESTAMP" => ScalarFunctions::ToTimestamp,
            "TRIM" => ScalarFunctions::Trim,
            "TRUNC" => ScalarFunctions::Trunc,
            "UPPER" => ScalarFunctions::Upper,
            other => ScalarFunctions::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ScalarFunctions {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ScalarFunctions::from(s))
    }
}
impl ScalarFunctions {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ScalarFunctions::Abs => "ABS",
            ScalarFunctions::Cast => "CAST",
            ScalarFunctions::Ceiling => "CEILING",
            ScalarFunctions::Coalesce => "COALESCE",
            ScalarFunctions::Convert => "CONVERT",
            ScalarFunctions::CurrentDate => "CURRENT_DATE",
            ScalarFunctions::Dateadd => "DATEADD",
            ScalarFunctions::Extract => "EXTRACT",
            ScalarFunctions::Floor => "FLOOR",
            ScalarFunctions::Getdate => "GETDATE",
            ScalarFunctions::Ln => "LN",
            ScalarFunctions::Log => "LOG",
            ScalarFunctions::Lower => "LOWER",
            ScalarFunctions::Round => "ROUND",
            ScalarFunctions::Rtrim => "RTRIM",
            ScalarFunctions::Sqrt => "SQRT",
            ScalarFunctions::Substring => "SUBSTRING",
            ScalarFunctions::ToChar => "TO_CHAR",
            ScalarFunctions::ToDate => "TO_DATE",
            ScalarFunctions::ToNumber => "TO_NUMBER",
            ScalarFunctions::ToTimestamp => "TO_TIMESTAMP",
            ScalarFunctions::Trim => "TRIM",
            ScalarFunctions::Trunc => "TRUNC",
            ScalarFunctions::Upper => "UPPER",
            ScalarFunctions::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ABS",
            "CAST",
            "CEILING",
            "COALESCE",
            "CONVERT",
            "CURRENT_DATE",
            "DATEADD",
            "EXTRACT",
            "FLOOR",
            "GETDATE",
            "LN",
            "LOG",
            "LOWER",
            "ROUND",
            "RTRIM",
            "SQRT",
            "SUBSTRING",
            "TO_CHAR",
            "TO_DATE",
            "TO_NUMBER",
            "TO_TIMESTAMP",
            "TRIM",
            "TRUNC",
            "UPPER",
        ]
    }
}
impl ::std::convert::AsRef<str> for ScalarFunctions {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ScalarFunctions {
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
impl ::std::fmt::Display for ScalarFunctions {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ScalarFunctions::Abs => write!(f, "ABS"),
            ScalarFunctions::Cast => write!(f, "CAST"),
            ScalarFunctions::Ceiling => write!(f, "CEILING"),
            ScalarFunctions::Coalesce => write!(f, "COALESCE"),
            ScalarFunctions::Convert => write!(f, "CONVERT"),
            ScalarFunctions::CurrentDate => write!(f, "CURRENT_DATE"),
            ScalarFunctions::Dateadd => write!(f, "DATEADD"),
            ScalarFunctions::Extract => write!(f, "EXTRACT"),
            ScalarFunctions::Floor => write!(f, "FLOOR"),
            ScalarFunctions::Getdate => write!(f, "GETDATE"),
            ScalarFunctions::Ln => write!(f, "LN"),
            ScalarFunctions::Log => write!(f, "LOG"),
            ScalarFunctions::Lower => write!(f, "LOWER"),
            ScalarFunctions::Round => write!(f, "ROUND"),
            ScalarFunctions::Rtrim => write!(f, "RTRIM"),
            ScalarFunctions::Sqrt => write!(f, "SQRT"),
            ScalarFunctions::Substring => write!(f, "SUBSTRING"),
            ScalarFunctions::ToChar => write!(f, "TO_CHAR"),
            ScalarFunctions::ToDate => write!(f, "TO_DATE"),
            ScalarFunctions::ToNumber => write!(f, "TO_NUMBER"),
            ScalarFunctions::ToTimestamp => write!(f, "TO_TIMESTAMP"),
            ScalarFunctions::Trim => write!(f, "TRIM"),
            ScalarFunctions::Trunc => write!(f, "TRUNC"),
            ScalarFunctions::Upper => write!(f, "UPPER"),
            ScalarFunctions::Unknown(value) => write!(f, "{}", value),
        }
    }
}
