// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DescribeEndpointsMode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let describeendpointsmode = unimplemented!();
/// match describeendpointsmode {
///     DescribeEndpointsMode::Default => { /* ... */ },
///     DescribeEndpointsMode::GetOnly => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `describeendpointsmode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DescribeEndpointsMode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DescribeEndpointsMode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DescribeEndpointsMode::NewFeature` is defined.
/// Specifically, when `describeendpointsmode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DescribeEndpointsMode::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Optional field, defaults to DEFAULT. Specify DEFAULT for this operation to return your endpoints if any exist, or to create an endpoint for you and return it if one doesn't already exist. Specify GET_ONLY to return your endpoints if any exist, or an empty list if none exist.
#[deprecated(
    note = "DescribeEndpoints and account specific endpoints are no longer required. We recommend that you send your requests directly to the regional endpoint instead."
)]
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum DescribeEndpointsMode {
    #[allow(missing_docs)] // documentation missing in model
    Default,
    #[allow(missing_docs)] // documentation missing in model
    GetOnly,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DescribeEndpointsMode {
    fn from(s: &str) -> Self {
        match s {
            "DEFAULT" => DescribeEndpointsMode::Default,
            "GET_ONLY" => DescribeEndpointsMode::GetOnly,
            other => DescribeEndpointsMode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DescribeEndpointsMode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DescribeEndpointsMode::from(s))
    }
}
impl DescribeEndpointsMode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DescribeEndpointsMode::Default => "DEFAULT",
            DescribeEndpointsMode::GetOnly => "GET_ONLY",
            DescribeEndpointsMode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["DEFAULT", "GET_ONLY"]
    }
}
impl ::std::convert::AsRef<str> for DescribeEndpointsMode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DescribeEndpointsMode {
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
impl ::std::fmt::Display for DescribeEndpointsMode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DescribeEndpointsMode::Default => write!(f, "DEFAULT"),
            DescribeEndpointsMode::GetOnly => write!(f, "GET_ONLY"),
            DescribeEndpointsMode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
