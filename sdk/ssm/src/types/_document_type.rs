// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DocumentType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let documenttype = unimplemented!();
/// match documenttype {
///     DocumentType::ApplicationConfiguration => { /* ... */ },
///     DocumentType::ApplicationConfigurationSchema => { /* ... */ },
///     DocumentType::AutoApprovalPolicy => { /* ... */ },
///     DocumentType::Automation => { /* ... */ },
///     DocumentType::ChangeTemplate => { /* ... */ },
///     DocumentType::ChangeCalendar => { /* ... */ },
///     DocumentType::CloudFormation => { /* ... */ },
///     DocumentType::Command => { /* ... */ },
///     DocumentType::ConformancePackTemplate => { /* ... */ },
///     DocumentType::DeploymentStrategy => { /* ... */ },
///     DocumentType::ManualApprovalPolicy => { /* ... */ },
///     DocumentType::Package => { /* ... */ },
///     DocumentType::Policy => { /* ... */ },
///     DocumentType::ProblemAnalysis => { /* ... */ },
///     DocumentType::ProblemAnalysisTemplate => { /* ... */ },
///     DocumentType::QuickSetup => { /* ... */ },
///     DocumentType::Session => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `documenttype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DocumentType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DocumentType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DocumentType::NewFeature` is defined.
/// Specifically, when `documenttype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DocumentType::NewFeature` also yielding `"NewFeature"`.
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
pub enum DocumentType {
    #[allow(missing_docs)] // documentation missing in model
    ApplicationConfiguration,
    #[allow(missing_docs)] // documentation missing in model
    ApplicationConfigurationSchema,
    #[allow(missing_docs)] // documentation missing in model
    AutoApprovalPolicy,
    #[allow(missing_docs)] // documentation missing in model
    Automation,
    #[allow(missing_docs)] // documentation missing in model
    ChangeTemplate,
    #[allow(missing_docs)] // documentation missing in model
    ChangeCalendar,
    #[allow(missing_docs)] // documentation missing in model
    CloudFormation,
    #[allow(missing_docs)] // documentation missing in model
    Command,
    #[allow(missing_docs)] // documentation missing in model
    ConformancePackTemplate,
    #[allow(missing_docs)] // documentation missing in model
    DeploymentStrategy,
    #[allow(missing_docs)] // documentation missing in model
    ManualApprovalPolicy,
    #[allow(missing_docs)] // documentation missing in model
    Package,
    #[allow(missing_docs)] // documentation missing in model
    Policy,
    #[allow(missing_docs)] // documentation missing in model
    ProblemAnalysis,
    #[allow(missing_docs)] // documentation missing in model
    ProblemAnalysisTemplate,
    #[allow(missing_docs)] // documentation missing in model
    QuickSetup,
    #[allow(missing_docs)] // documentation missing in model
    Session,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DocumentType {
    fn from(s: &str) -> Self {
        match s {
            "ApplicationConfiguration" => DocumentType::ApplicationConfiguration,
            "ApplicationConfigurationSchema" => DocumentType::ApplicationConfigurationSchema,
            "AutoApprovalPolicy" => DocumentType::AutoApprovalPolicy,
            "Automation" => DocumentType::Automation,
            "Automation.ChangeTemplate" => DocumentType::ChangeTemplate,
            "ChangeCalendar" => DocumentType::ChangeCalendar,
            "CloudFormation" => DocumentType::CloudFormation,
            "Command" => DocumentType::Command,
            "ConformancePackTemplate" => DocumentType::ConformancePackTemplate,
            "DeploymentStrategy" => DocumentType::DeploymentStrategy,
            "ManualApprovalPolicy" => DocumentType::ManualApprovalPolicy,
            "Package" => DocumentType::Package,
            "Policy" => DocumentType::Policy,
            "ProblemAnalysis" => DocumentType::ProblemAnalysis,
            "ProblemAnalysisTemplate" => DocumentType::ProblemAnalysisTemplate,
            "QuickSetup" => DocumentType::QuickSetup,
            "Session" => DocumentType::Session,
            other => DocumentType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DocumentType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DocumentType::from(s))
    }
}
impl DocumentType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DocumentType::ApplicationConfiguration => "ApplicationConfiguration",
            DocumentType::ApplicationConfigurationSchema => "ApplicationConfigurationSchema",
            DocumentType::AutoApprovalPolicy => "AutoApprovalPolicy",
            DocumentType::Automation => "Automation",
            DocumentType::ChangeTemplate => "Automation.ChangeTemplate",
            DocumentType::ChangeCalendar => "ChangeCalendar",
            DocumentType::CloudFormation => "CloudFormation",
            DocumentType::Command => "Command",
            DocumentType::ConformancePackTemplate => "ConformancePackTemplate",
            DocumentType::DeploymentStrategy => "DeploymentStrategy",
            DocumentType::ManualApprovalPolicy => "ManualApprovalPolicy",
            DocumentType::Package => "Package",
            DocumentType::Policy => "Policy",
            DocumentType::ProblemAnalysis => "ProblemAnalysis",
            DocumentType::ProblemAnalysisTemplate => "ProblemAnalysisTemplate",
            DocumentType::QuickSetup => "QuickSetup",
            DocumentType::Session => "Session",
            DocumentType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ApplicationConfiguration",
            "ApplicationConfigurationSchema",
            "AutoApprovalPolicy",
            "Automation",
            "Automation.ChangeTemplate",
            "ChangeCalendar",
            "CloudFormation",
            "Command",
            "ConformancePackTemplate",
            "DeploymentStrategy",
            "ManualApprovalPolicy",
            "Package",
            "Policy",
            "ProblemAnalysis",
            "ProblemAnalysisTemplate",
            "QuickSetup",
            "Session",
        ]
    }
}
impl ::std::convert::AsRef<str> for DocumentType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DocumentType {
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
impl ::std::fmt::Display for DocumentType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DocumentType::ApplicationConfiguration => write!(f, "ApplicationConfiguration"),
            DocumentType::ApplicationConfigurationSchema => write!(f, "ApplicationConfigurationSchema"),
            DocumentType::AutoApprovalPolicy => write!(f, "AutoApprovalPolicy"),
            DocumentType::Automation => write!(f, "Automation"),
            DocumentType::ChangeTemplate => write!(f, "Automation.ChangeTemplate"),
            DocumentType::ChangeCalendar => write!(f, "ChangeCalendar"),
            DocumentType::CloudFormation => write!(f, "CloudFormation"),
            DocumentType::Command => write!(f, "Command"),
            DocumentType::ConformancePackTemplate => write!(f, "ConformancePackTemplate"),
            DocumentType::DeploymentStrategy => write!(f, "DeploymentStrategy"),
            DocumentType::ManualApprovalPolicy => write!(f, "ManualApprovalPolicy"),
            DocumentType::Package => write!(f, "Package"),
            DocumentType::Policy => write!(f, "Policy"),
            DocumentType::ProblemAnalysis => write!(f, "ProblemAnalysis"),
            DocumentType::ProblemAnalysisTemplate => write!(f, "ProblemAnalysisTemplate"),
            DocumentType::QuickSetup => write!(f, "QuickSetup"),
            DocumentType::Session => write!(f, "Session"),
            DocumentType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
