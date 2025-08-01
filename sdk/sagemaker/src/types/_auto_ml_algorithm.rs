// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AutoMlAlgorithm`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let automlalgorithm = unimplemented!();
/// match automlalgorithm {
///     AutoMlAlgorithm::Arima => { /* ... */ },
///     AutoMlAlgorithm::Catboost => { /* ... */ },
///     AutoMlAlgorithm::CnnQr => { /* ... */ },
///     AutoMlAlgorithm::Deepar => { /* ... */ },
///     AutoMlAlgorithm::Ets => { /* ... */ },
///     AutoMlAlgorithm::ExtraTrees => { /* ... */ },
///     AutoMlAlgorithm::Fastai => { /* ... */ },
///     AutoMlAlgorithm::Lightgbm => { /* ... */ },
///     AutoMlAlgorithm::LinearLearner => { /* ... */ },
///     AutoMlAlgorithm::Mlp => { /* ... */ },
///     AutoMlAlgorithm::NnTorch => { /* ... */ },
///     AutoMlAlgorithm::Npts => { /* ... */ },
///     AutoMlAlgorithm::Prophet => { /* ... */ },
///     AutoMlAlgorithm::Randomforest => { /* ... */ },
///     AutoMlAlgorithm::Xgboost => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `automlalgorithm` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AutoMlAlgorithm::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AutoMlAlgorithm::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AutoMlAlgorithm::NewFeature` is defined.
/// Specifically, when `automlalgorithm` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AutoMlAlgorithm::NewFeature` also yielding `"NewFeature"`.
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
pub enum AutoMlAlgorithm {
    #[allow(missing_docs)] // documentation missing in model
    Arima,
    #[allow(missing_docs)] // documentation missing in model
    Catboost,
    #[allow(missing_docs)] // documentation missing in model
    CnnQr,
    #[allow(missing_docs)] // documentation missing in model
    Deepar,
    #[allow(missing_docs)] // documentation missing in model
    Ets,
    #[allow(missing_docs)] // documentation missing in model
    ExtraTrees,
    #[allow(missing_docs)] // documentation missing in model
    Fastai,
    #[allow(missing_docs)] // documentation missing in model
    Lightgbm,
    #[allow(missing_docs)] // documentation missing in model
    LinearLearner,
    #[allow(missing_docs)] // documentation missing in model
    Mlp,
    #[allow(missing_docs)] // documentation missing in model
    NnTorch,
    #[allow(missing_docs)] // documentation missing in model
    Npts,
    #[allow(missing_docs)] // documentation missing in model
    Prophet,
    #[allow(missing_docs)] // documentation missing in model
    Randomforest,
    #[allow(missing_docs)] // documentation missing in model
    Xgboost,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AutoMlAlgorithm {
    fn from(s: &str) -> Self {
        match s {
            "arima" => AutoMlAlgorithm::Arima,
            "catboost" => AutoMlAlgorithm::Catboost,
            "cnn-qr" => AutoMlAlgorithm::CnnQr,
            "deepar" => AutoMlAlgorithm::Deepar,
            "ets" => AutoMlAlgorithm::Ets,
            "extra-trees" => AutoMlAlgorithm::ExtraTrees,
            "fastai" => AutoMlAlgorithm::Fastai,
            "lightgbm" => AutoMlAlgorithm::Lightgbm,
            "linear-learner" => AutoMlAlgorithm::LinearLearner,
            "mlp" => AutoMlAlgorithm::Mlp,
            "nn-torch" => AutoMlAlgorithm::NnTorch,
            "npts" => AutoMlAlgorithm::Npts,
            "prophet" => AutoMlAlgorithm::Prophet,
            "randomforest" => AutoMlAlgorithm::Randomforest,
            "xgboost" => AutoMlAlgorithm::Xgboost,
            other => AutoMlAlgorithm::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AutoMlAlgorithm {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AutoMlAlgorithm::from(s))
    }
}
impl AutoMlAlgorithm {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AutoMlAlgorithm::Arima => "arima",
            AutoMlAlgorithm::Catboost => "catboost",
            AutoMlAlgorithm::CnnQr => "cnn-qr",
            AutoMlAlgorithm::Deepar => "deepar",
            AutoMlAlgorithm::Ets => "ets",
            AutoMlAlgorithm::ExtraTrees => "extra-trees",
            AutoMlAlgorithm::Fastai => "fastai",
            AutoMlAlgorithm::Lightgbm => "lightgbm",
            AutoMlAlgorithm::LinearLearner => "linear-learner",
            AutoMlAlgorithm::Mlp => "mlp",
            AutoMlAlgorithm::NnTorch => "nn-torch",
            AutoMlAlgorithm::Npts => "npts",
            AutoMlAlgorithm::Prophet => "prophet",
            AutoMlAlgorithm::Randomforest => "randomforest",
            AutoMlAlgorithm::Xgboost => "xgboost",
            AutoMlAlgorithm::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "arima",
            "catboost",
            "cnn-qr",
            "deepar",
            "ets",
            "extra-trees",
            "fastai",
            "lightgbm",
            "linear-learner",
            "mlp",
            "nn-torch",
            "npts",
            "prophet",
            "randomforest",
            "xgboost",
        ]
    }
}
impl ::std::convert::AsRef<str> for AutoMlAlgorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AutoMlAlgorithm {
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
impl ::std::fmt::Display for AutoMlAlgorithm {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AutoMlAlgorithm::Arima => write!(f, "arima"),
            AutoMlAlgorithm::Catboost => write!(f, "catboost"),
            AutoMlAlgorithm::CnnQr => write!(f, "cnn-qr"),
            AutoMlAlgorithm::Deepar => write!(f, "deepar"),
            AutoMlAlgorithm::Ets => write!(f, "ets"),
            AutoMlAlgorithm::ExtraTrees => write!(f, "extra-trees"),
            AutoMlAlgorithm::Fastai => write!(f, "fastai"),
            AutoMlAlgorithm::Lightgbm => write!(f, "lightgbm"),
            AutoMlAlgorithm::LinearLearner => write!(f, "linear-learner"),
            AutoMlAlgorithm::Mlp => write!(f, "mlp"),
            AutoMlAlgorithm::NnTorch => write!(f, "nn-torch"),
            AutoMlAlgorithm::Npts => write!(f, "npts"),
            AutoMlAlgorithm::Prophet => write!(f, "prophet"),
            AutoMlAlgorithm::Randomforest => write!(f, "randomforest"),
            AutoMlAlgorithm::Xgboost => write!(f, "xgboost"),
            AutoMlAlgorithm::Unknown(value) => write!(f, "{}", value),
        }
    }
}
