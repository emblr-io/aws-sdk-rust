// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EvaluationFilterVariable`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let evaluationfiltervariable = unimplemented!();
/// match evaluationfiltervariable {
///     EvaluationFilterVariable::CreatedAt => { /* ... */ },
///     EvaluationFilterVariable::DatasourceId => { /* ... */ },
///     EvaluationFilterVariable::DataUri => { /* ... */ },
///     EvaluationFilterVariable::IamUser => { /* ... */ },
///     EvaluationFilterVariable::LastUpdatedAt => { /* ... */ },
///     EvaluationFilterVariable::MlModelId => { /* ... */ },
///     EvaluationFilterVariable::Name => { /* ... */ },
///     EvaluationFilterVariable::Status => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `evaluationfiltervariable` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EvaluationFilterVariable::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EvaluationFilterVariable::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EvaluationFilterVariable::NewFeature` is defined.
/// Specifically, when `evaluationfiltervariable` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EvaluationFilterVariable::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>A list of the variables to use in searching or filtering <code>Evaluation</code>.</p>
/// <ul>
/// <li>
/// <p>
/// <code>CreatedAt</code> - Sets the search criteria to <code>Evaluation</code> creation date.</p>
/// </li>
/// <li>
/// <p>
/// <code>Status</code> - Sets the search criteria to <code>Evaluation</code> status.</p>
/// </li>
/// <li>
/// <p>
/// <code>Name</code> - Sets the search criteria to the contents of <code>Evaluation</code>
/// <b> </b>
/// <code>Name</code>.</p>
/// </li>
/// <li>
/// <p>
/// <code>IAMUser</code> - Sets the search criteria to the user account that invoked an evaluation.</p>
/// </li>
/// <li>
/// <p>
/// <code>MLModelId</code> - Sets the search criteria to the <code>Predictor</code> that was evaluated.</p>
/// </li>
/// <li>
/// <p>
/// <code>DataSourceId</code> - Sets the search criteria to the <code>DataSource</code> used in evaluation.</p>
/// </li>
/// <li>
/// <p>
/// <code>DataUri</code> - Sets the search criteria to the data file(s) used in evaluation. The URL can identify either a file or an Amazon Simple Storage Service (Amazon S3) bucket or directory.</p>
/// </li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum EvaluationFilterVariable {
    #[allow(missing_docs)] // documentation missing in model
    CreatedAt,
    #[allow(missing_docs)] // documentation missing in model
    DatasourceId,
    #[allow(missing_docs)] // documentation missing in model
    DataUri,
    #[allow(missing_docs)] // documentation missing in model
    IamUser,
    #[allow(missing_docs)] // documentation missing in model
    LastUpdatedAt,
    #[allow(missing_docs)] // documentation missing in model
    MlModelId,
    #[allow(missing_docs)] // documentation missing in model
    Name,
    #[allow(missing_docs)] // documentation missing in model
    Status,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EvaluationFilterVariable {
    fn from(s: &str) -> Self {
        match s {
            "CreatedAt" => EvaluationFilterVariable::CreatedAt,
            "DataSourceId" => EvaluationFilterVariable::DatasourceId,
            "DataURI" => EvaluationFilterVariable::DataUri,
            "IAMUser" => EvaluationFilterVariable::IamUser,
            "LastUpdatedAt" => EvaluationFilterVariable::LastUpdatedAt,
            "MLModelId" => EvaluationFilterVariable::MlModelId,
            "Name" => EvaluationFilterVariable::Name,
            "Status" => EvaluationFilterVariable::Status,
            other => EvaluationFilterVariable::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EvaluationFilterVariable {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EvaluationFilterVariable::from(s))
    }
}
impl EvaluationFilterVariable {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EvaluationFilterVariable::CreatedAt => "CreatedAt",
            EvaluationFilterVariable::DatasourceId => "DataSourceId",
            EvaluationFilterVariable::DataUri => "DataURI",
            EvaluationFilterVariable::IamUser => "IAMUser",
            EvaluationFilterVariable::LastUpdatedAt => "LastUpdatedAt",
            EvaluationFilterVariable::MlModelId => "MLModelId",
            EvaluationFilterVariable::Name => "Name",
            EvaluationFilterVariable::Status => "Status",
            EvaluationFilterVariable::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CreatedAt",
            "DataSourceId",
            "DataURI",
            "IAMUser",
            "LastUpdatedAt",
            "MLModelId",
            "Name",
            "Status",
        ]
    }
}
impl ::std::convert::AsRef<str> for EvaluationFilterVariable {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EvaluationFilterVariable {
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
impl ::std::fmt::Display for EvaluationFilterVariable {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EvaluationFilterVariable::CreatedAt => write!(f, "CreatedAt"),
            EvaluationFilterVariable::DatasourceId => write!(f, "DataSourceId"),
            EvaluationFilterVariable::DataUri => write!(f, "DataURI"),
            EvaluationFilterVariable::IamUser => write!(f, "IAMUser"),
            EvaluationFilterVariable::LastUpdatedAt => write!(f, "LastUpdatedAt"),
            EvaluationFilterVariable::MlModelId => write!(f, "MLModelId"),
            EvaluationFilterVariable::Name => write!(f, "Name"),
            EvaluationFilterVariable::Status => write!(f, "Status"),
            EvaluationFilterVariable::Unknown(value) => write!(f, "{}", value),
        }
    }
}
