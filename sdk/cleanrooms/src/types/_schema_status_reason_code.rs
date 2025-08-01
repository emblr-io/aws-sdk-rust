// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `SchemaStatusReasonCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let schemastatusreasoncode = unimplemented!();
/// match schemastatusreasoncode {
///     SchemaStatusReasonCode::AdditionalAnalysesNotAllowed => { /* ... */ },
///     SchemaStatusReasonCode::AdditionalAnalysesNotConfigured => { /* ... */ },
///     SchemaStatusReasonCode::AnalysisProvidersNotConfigured => { /* ... */ },
///     SchemaStatusReasonCode::AnalysisRuleMissing => { /* ... */ },
///     SchemaStatusReasonCode::AnalysisRuleTypesNotCompatible => { /* ... */ },
///     SchemaStatusReasonCode::AnalysisTemplatesNotConfigured => { /* ... */ },
///     SchemaStatusReasonCode::CollaborationAnalysisRuleNotConfigured => { /* ... */ },
///     SchemaStatusReasonCode::DifferentialPrivacyPolicyNotConfigured => { /* ... */ },
///     SchemaStatusReasonCode::IdMappingTableNotPopulated => { /* ... */ },
///     SchemaStatusReasonCode::ResultReceiversNotAllowed => { /* ... */ },
///     SchemaStatusReasonCode::ResultReceiversNotConfigured => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `schemastatusreasoncode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `SchemaStatusReasonCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `SchemaStatusReasonCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `SchemaStatusReasonCode::NewFeature` is defined.
/// Specifically, when `schemastatusreasoncode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `SchemaStatusReasonCode::NewFeature` also yielding `"NewFeature"`.
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
pub enum SchemaStatusReasonCode {
    #[allow(missing_docs)] // documentation missing in model
    AdditionalAnalysesNotAllowed,
    #[allow(missing_docs)] // documentation missing in model
    AdditionalAnalysesNotConfigured,
    #[allow(missing_docs)] // documentation missing in model
    AnalysisProvidersNotConfigured,
    #[allow(missing_docs)] // documentation missing in model
    AnalysisRuleMissing,
    #[allow(missing_docs)] // documentation missing in model
    AnalysisRuleTypesNotCompatible,
    #[allow(missing_docs)] // documentation missing in model
    AnalysisTemplatesNotConfigured,
    #[allow(missing_docs)] // documentation missing in model
    CollaborationAnalysisRuleNotConfigured,
    #[allow(missing_docs)] // documentation missing in model
    DifferentialPrivacyPolicyNotConfigured,
    #[allow(missing_docs)] // documentation missing in model
    IdMappingTableNotPopulated,
    #[allow(missing_docs)] // documentation missing in model
    ResultReceiversNotAllowed,
    #[allow(missing_docs)] // documentation missing in model
    ResultReceiversNotConfigured,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for SchemaStatusReasonCode {
    fn from(s: &str) -> Self {
        match s {
            "ADDITIONAL_ANALYSES_NOT_ALLOWED" => SchemaStatusReasonCode::AdditionalAnalysesNotAllowed,
            "ADDITIONAL_ANALYSES_NOT_CONFIGURED" => SchemaStatusReasonCode::AdditionalAnalysesNotConfigured,
            "ANALYSIS_PROVIDERS_NOT_CONFIGURED" => SchemaStatusReasonCode::AnalysisProvidersNotConfigured,
            "ANALYSIS_RULE_MISSING" => SchemaStatusReasonCode::AnalysisRuleMissing,
            "ANALYSIS_RULE_TYPES_NOT_COMPATIBLE" => SchemaStatusReasonCode::AnalysisRuleTypesNotCompatible,
            "ANALYSIS_TEMPLATES_NOT_CONFIGURED" => SchemaStatusReasonCode::AnalysisTemplatesNotConfigured,
            "COLLABORATION_ANALYSIS_RULE_NOT_CONFIGURED" => SchemaStatusReasonCode::CollaborationAnalysisRuleNotConfigured,
            "DIFFERENTIAL_PRIVACY_POLICY_NOT_CONFIGURED" => SchemaStatusReasonCode::DifferentialPrivacyPolicyNotConfigured,
            "ID_MAPPING_TABLE_NOT_POPULATED" => SchemaStatusReasonCode::IdMappingTableNotPopulated,
            "RESULT_RECEIVERS_NOT_ALLOWED" => SchemaStatusReasonCode::ResultReceiversNotAllowed,
            "RESULT_RECEIVERS_NOT_CONFIGURED" => SchemaStatusReasonCode::ResultReceiversNotConfigured,
            other => SchemaStatusReasonCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for SchemaStatusReasonCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(SchemaStatusReasonCode::from(s))
    }
}
impl SchemaStatusReasonCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            SchemaStatusReasonCode::AdditionalAnalysesNotAllowed => "ADDITIONAL_ANALYSES_NOT_ALLOWED",
            SchemaStatusReasonCode::AdditionalAnalysesNotConfigured => "ADDITIONAL_ANALYSES_NOT_CONFIGURED",
            SchemaStatusReasonCode::AnalysisProvidersNotConfigured => "ANALYSIS_PROVIDERS_NOT_CONFIGURED",
            SchemaStatusReasonCode::AnalysisRuleMissing => "ANALYSIS_RULE_MISSING",
            SchemaStatusReasonCode::AnalysisRuleTypesNotCompatible => "ANALYSIS_RULE_TYPES_NOT_COMPATIBLE",
            SchemaStatusReasonCode::AnalysisTemplatesNotConfigured => "ANALYSIS_TEMPLATES_NOT_CONFIGURED",
            SchemaStatusReasonCode::CollaborationAnalysisRuleNotConfigured => "COLLABORATION_ANALYSIS_RULE_NOT_CONFIGURED",
            SchemaStatusReasonCode::DifferentialPrivacyPolicyNotConfigured => "DIFFERENTIAL_PRIVACY_POLICY_NOT_CONFIGURED",
            SchemaStatusReasonCode::IdMappingTableNotPopulated => "ID_MAPPING_TABLE_NOT_POPULATED",
            SchemaStatusReasonCode::ResultReceiversNotAllowed => "RESULT_RECEIVERS_NOT_ALLOWED",
            SchemaStatusReasonCode::ResultReceiversNotConfigured => "RESULT_RECEIVERS_NOT_CONFIGURED",
            SchemaStatusReasonCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ADDITIONAL_ANALYSES_NOT_ALLOWED",
            "ADDITIONAL_ANALYSES_NOT_CONFIGURED",
            "ANALYSIS_PROVIDERS_NOT_CONFIGURED",
            "ANALYSIS_RULE_MISSING",
            "ANALYSIS_RULE_TYPES_NOT_COMPATIBLE",
            "ANALYSIS_TEMPLATES_NOT_CONFIGURED",
            "COLLABORATION_ANALYSIS_RULE_NOT_CONFIGURED",
            "DIFFERENTIAL_PRIVACY_POLICY_NOT_CONFIGURED",
            "ID_MAPPING_TABLE_NOT_POPULATED",
            "RESULT_RECEIVERS_NOT_ALLOWED",
            "RESULT_RECEIVERS_NOT_CONFIGURED",
        ]
    }
}
impl ::std::convert::AsRef<str> for SchemaStatusReasonCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl SchemaStatusReasonCode {
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
impl ::std::fmt::Display for SchemaStatusReasonCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            SchemaStatusReasonCode::AdditionalAnalysesNotAllowed => write!(f, "ADDITIONAL_ANALYSES_NOT_ALLOWED"),
            SchemaStatusReasonCode::AdditionalAnalysesNotConfigured => write!(f, "ADDITIONAL_ANALYSES_NOT_CONFIGURED"),
            SchemaStatusReasonCode::AnalysisProvidersNotConfigured => write!(f, "ANALYSIS_PROVIDERS_NOT_CONFIGURED"),
            SchemaStatusReasonCode::AnalysisRuleMissing => write!(f, "ANALYSIS_RULE_MISSING"),
            SchemaStatusReasonCode::AnalysisRuleTypesNotCompatible => write!(f, "ANALYSIS_RULE_TYPES_NOT_COMPATIBLE"),
            SchemaStatusReasonCode::AnalysisTemplatesNotConfigured => write!(f, "ANALYSIS_TEMPLATES_NOT_CONFIGURED"),
            SchemaStatusReasonCode::CollaborationAnalysisRuleNotConfigured => write!(f, "COLLABORATION_ANALYSIS_RULE_NOT_CONFIGURED"),
            SchemaStatusReasonCode::DifferentialPrivacyPolicyNotConfigured => write!(f, "DIFFERENTIAL_PRIVACY_POLICY_NOT_CONFIGURED"),
            SchemaStatusReasonCode::IdMappingTableNotPopulated => write!(f, "ID_MAPPING_TABLE_NOT_POPULATED"),
            SchemaStatusReasonCode::ResultReceiversNotAllowed => write!(f, "RESULT_RECEIVERS_NOT_ALLOWED"),
            SchemaStatusReasonCode::ResultReceiversNotConfigured => write!(f, "RESULT_RECEIVERS_NOT_CONFIGURED"),
            SchemaStatusReasonCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
