// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AwsLogSourceName`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let awslogsourcename = unimplemented!();
/// match awslogsourcename {
///     AwsLogSourceName::CloudTrailMgmt => { /* ... */ },
///     AwsLogSourceName::EksAudit => { /* ... */ },
///     AwsLogSourceName::LambdaExecution => { /* ... */ },
///     AwsLogSourceName::Route53 => { /* ... */ },
///     AwsLogSourceName::S3Data => { /* ... */ },
///     AwsLogSourceName::ShFindings => { /* ... */ },
///     AwsLogSourceName::VpcFlow => { /* ... */ },
///     AwsLogSourceName::Waf => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `awslogsourcename` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AwsLogSourceName::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AwsLogSourceName::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AwsLogSourceName::NewFeature` is defined.
/// Specifically, when `awslogsourcename` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AwsLogSourceName::NewFeature` also yielding `"NewFeature"`.
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
pub enum AwsLogSourceName {
    #[allow(missing_docs)] // documentation missing in model
    CloudTrailMgmt,
    #[allow(missing_docs)] // documentation missing in model
    EksAudit,
    #[allow(missing_docs)] // documentation missing in model
    LambdaExecution,
    #[allow(missing_docs)] // documentation missing in model
    Route53,
    #[allow(missing_docs)] // documentation missing in model
    S3Data,
    #[allow(missing_docs)] // documentation missing in model
    ShFindings,
    #[allow(missing_docs)] // documentation missing in model
    VpcFlow,
    #[allow(missing_docs)] // documentation missing in model
    Waf,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AwsLogSourceName {
    fn from(s: &str) -> Self {
        match s {
            "CLOUD_TRAIL_MGMT" => AwsLogSourceName::CloudTrailMgmt,
            "EKS_AUDIT" => AwsLogSourceName::EksAudit,
            "LAMBDA_EXECUTION" => AwsLogSourceName::LambdaExecution,
            "ROUTE53" => AwsLogSourceName::Route53,
            "S3_DATA" => AwsLogSourceName::S3Data,
            "SH_FINDINGS" => AwsLogSourceName::ShFindings,
            "VPC_FLOW" => AwsLogSourceName::VpcFlow,
            "WAF" => AwsLogSourceName::Waf,
            other => AwsLogSourceName::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AwsLogSourceName {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AwsLogSourceName::from(s))
    }
}
impl AwsLogSourceName {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AwsLogSourceName::CloudTrailMgmt => "CLOUD_TRAIL_MGMT",
            AwsLogSourceName::EksAudit => "EKS_AUDIT",
            AwsLogSourceName::LambdaExecution => "LAMBDA_EXECUTION",
            AwsLogSourceName::Route53 => "ROUTE53",
            AwsLogSourceName::S3Data => "S3_DATA",
            AwsLogSourceName::ShFindings => "SH_FINDINGS",
            AwsLogSourceName::VpcFlow => "VPC_FLOW",
            AwsLogSourceName::Waf => "WAF",
            AwsLogSourceName::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CLOUD_TRAIL_MGMT",
            "EKS_AUDIT",
            "LAMBDA_EXECUTION",
            "ROUTE53",
            "S3_DATA",
            "SH_FINDINGS",
            "VPC_FLOW",
            "WAF",
        ]
    }
}
impl ::std::convert::AsRef<str> for AwsLogSourceName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AwsLogSourceName {
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
impl ::std::fmt::Display for AwsLogSourceName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AwsLogSourceName::CloudTrailMgmt => write!(f, "CLOUD_TRAIL_MGMT"),
            AwsLogSourceName::EksAudit => write!(f, "EKS_AUDIT"),
            AwsLogSourceName::LambdaExecution => write!(f, "LAMBDA_EXECUTION"),
            AwsLogSourceName::Route53 => write!(f, "ROUTE53"),
            AwsLogSourceName::S3Data => write!(f, "S3_DATA"),
            AwsLogSourceName::ShFindings => write!(f, "SH_FINDINGS"),
            AwsLogSourceName::VpcFlow => write!(f, "VPC_FLOW"),
            AwsLogSourceName::Waf => write!(f, "WAF"),
            AwsLogSourceName::Unknown(value) => write!(f, "{}", value),
        }
    }
}
