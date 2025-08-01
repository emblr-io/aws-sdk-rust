// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ComparisonMethodType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let comparisonmethodtype = unimplemented!();
/// match comparisonmethodtype {
///     ComparisonMethodType::Diff => { /* ... */ },
///     ComparisonMethodType::DiffAsPerc => { /* ... */ },
///     ComparisonMethodType::MovingAverage => { /* ... */ },
///     ComparisonMethodType::PercentOfTotal => { /* ... */ },
///     ComparisonMethodType::PercDiff => { /* ... */ },
///     ComparisonMethodType::PopCurrentDiff => { /* ... */ },
///     ComparisonMethodType::PopCurrentDiffAsPerc => { /* ... */ },
///     ComparisonMethodType::PopOvertimeDiff => { /* ... */ },
///     ComparisonMethodType::PopOvertimeDiffAsPerc => { /* ... */ },
///     ComparisonMethodType::RunningSum => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `comparisonmethodtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ComparisonMethodType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ComparisonMethodType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ComparisonMethodType::NewFeature` is defined.
/// Specifically, when `comparisonmethodtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ComparisonMethodType::NewFeature` also yielding `"NewFeature"`.
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
pub enum ComparisonMethodType {
    #[allow(missing_docs)] // documentation missing in model
    Diff,
    #[allow(missing_docs)] // documentation missing in model
    DiffAsPerc,
    #[allow(missing_docs)] // documentation missing in model
    MovingAverage,
    #[allow(missing_docs)] // documentation missing in model
    PercentOfTotal,
    #[allow(missing_docs)] // documentation missing in model
    PercDiff,
    #[allow(missing_docs)] // documentation missing in model
    PopCurrentDiff,
    #[allow(missing_docs)] // documentation missing in model
    PopCurrentDiffAsPerc,
    #[allow(missing_docs)] // documentation missing in model
    PopOvertimeDiff,
    #[allow(missing_docs)] // documentation missing in model
    PopOvertimeDiffAsPerc,
    #[allow(missing_docs)] // documentation missing in model
    RunningSum,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ComparisonMethodType {
    fn from(s: &str) -> Self {
        match s {
            "DIFF" => ComparisonMethodType::Diff,
            "DIFF_AS_PERC" => ComparisonMethodType::DiffAsPerc,
            "MOVING_AVERAGE" => ComparisonMethodType::MovingAverage,
            "PERCENT_OF_TOTAL" => ComparisonMethodType::PercentOfTotal,
            "PERC_DIFF" => ComparisonMethodType::PercDiff,
            "POP_CURRENT_DIFF" => ComparisonMethodType::PopCurrentDiff,
            "POP_CURRENT_DIFF_AS_PERC" => ComparisonMethodType::PopCurrentDiffAsPerc,
            "POP_OVERTIME_DIFF" => ComparisonMethodType::PopOvertimeDiff,
            "POP_OVERTIME_DIFF_AS_PERC" => ComparisonMethodType::PopOvertimeDiffAsPerc,
            "RUNNING_SUM" => ComparisonMethodType::RunningSum,
            other => ComparisonMethodType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ComparisonMethodType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ComparisonMethodType::from(s))
    }
}
impl ComparisonMethodType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ComparisonMethodType::Diff => "DIFF",
            ComparisonMethodType::DiffAsPerc => "DIFF_AS_PERC",
            ComparisonMethodType::MovingAverage => "MOVING_AVERAGE",
            ComparisonMethodType::PercentOfTotal => "PERCENT_OF_TOTAL",
            ComparisonMethodType::PercDiff => "PERC_DIFF",
            ComparisonMethodType::PopCurrentDiff => "POP_CURRENT_DIFF",
            ComparisonMethodType::PopCurrentDiffAsPerc => "POP_CURRENT_DIFF_AS_PERC",
            ComparisonMethodType::PopOvertimeDiff => "POP_OVERTIME_DIFF",
            ComparisonMethodType::PopOvertimeDiffAsPerc => "POP_OVERTIME_DIFF_AS_PERC",
            ComparisonMethodType::RunningSum => "RUNNING_SUM",
            ComparisonMethodType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DIFF",
            "DIFF_AS_PERC",
            "MOVING_AVERAGE",
            "PERCENT_OF_TOTAL",
            "PERC_DIFF",
            "POP_CURRENT_DIFF",
            "POP_CURRENT_DIFF_AS_PERC",
            "POP_OVERTIME_DIFF",
            "POP_OVERTIME_DIFF_AS_PERC",
            "RUNNING_SUM",
        ]
    }
}
impl ::std::convert::AsRef<str> for ComparisonMethodType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ComparisonMethodType {
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
impl ::std::fmt::Display for ComparisonMethodType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ComparisonMethodType::Diff => write!(f, "DIFF"),
            ComparisonMethodType::DiffAsPerc => write!(f, "DIFF_AS_PERC"),
            ComparisonMethodType::MovingAverage => write!(f, "MOVING_AVERAGE"),
            ComparisonMethodType::PercentOfTotal => write!(f, "PERCENT_OF_TOTAL"),
            ComparisonMethodType::PercDiff => write!(f, "PERC_DIFF"),
            ComparisonMethodType::PopCurrentDiff => write!(f, "POP_CURRENT_DIFF"),
            ComparisonMethodType::PopCurrentDiffAsPerc => write!(f, "POP_CURRENT_DIFF_AS_PERC"),
            ComparisonMethodType::PopOvertimeDiff => write!(f, "POP_OVERTIME_DIFF"),
            ComparisonMethodType::PopOvertimeDiffAsPerc => write!(f, "POP_OVERTIME_DIFF_AS_PERC"),
            ComparisonMethodType::RunningSum => write!(f, "RUNNING_SUM"),
            ComparisonMethodType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
