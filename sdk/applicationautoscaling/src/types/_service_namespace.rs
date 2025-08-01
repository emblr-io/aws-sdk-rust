// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ServiceNamespace`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let servicenamespace = unimplemented!();
/// match servicenamespace {
///     ServiceNamespace::Appstream => { /* ... */ },
///     ServiceNamespace::Cassandra => { /* ... */ },
///     ServiceNamespace::Comprehend => { /* ... */ },
///     ServiceNamespace::CustomResource => { /* ... */ },
///     ServiceNamespace::Dynamodb => { /* ... */ },
///     ServiceNamespace::Ec2 => { /* ... */ },
///     ServiceNamespace::Ecs => { /* ... */ },
///     ServiceNamespace::Elasticache => { /* ... */ },
///     ServiceNamespace::Emr => { /* ... */ },
///     ServiceNamespace::Kafka => { /* ... */ },
///     ServiceNamespace::Lambda => { /* ... */ },
///     ServiceNamespace::Neptune => { /* ... */ },
///     ServiceNamespace::Rds => { /* ... */ },
///     ServiceNamespace::Sagemaker => { /* ... */ },
///     ServiceNamespace::Workspaces => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `servicenamespace` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ServiceNamespace::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ServiceNamespace::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ServiceNamespace::NewFeature` is defined.
/// Specifically, when `servicenamespace` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ServiceNamespace::NewFeature` also yielding `"NewFeature"`.
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
pub enum ServiceNamespace {
    #[allow(missing_docs)] // documentation missing in model
    Appstream,
    #[allow(missing_docs)] // documentation missing in model
    Cassandra,
    #[allow(missing_docs)] // documentation missing in model
    Comprehend,
    #[allow(missing_docs)] // documentation missing in model
    CustomResource,
    #[allow(missing_docs)] // documentation missing in model
    Dynamodb,
    #[allow(missing_docs)] // documentation missing in model
    Ec2,
    #[allow(missing_docs)] // documentation missing in model
    Ecs,
    #[allow(missing_docs)] // documentation missing in model
    Elasticache,
    #[allow(missing_docs)] // documentation missing in model
    Emr,
    #[allow(missing_docs)] // documentation missing in model
    Kafka,
    #[allow(missing_docs)] // documentation missing in model
    Lambda,
    #[allow(missing_docs)] // documentation missing in model
    Neptune,
    #[allow(missing_docs)] // documentation missing in model
    Rds,
    #[allow(missing_docs)] // documentation missing in model
    Sagemaker,
    #[allow(missing_docs)] // documentation missing in model
    Workspaces,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ServiceNamespace {
    fn from(s: &str) -> Self {
        match s {
            "appstream" => ServiceNamespace::Appstream,
            "cassandra" => ServiceNamespace::Cassandra,
            "comprehend" => ServiceNamespace::Comprehend,
            "custom-resource" => ServiceNamespace::CustomResource,
            "dynamodb" => ServiceNamespace::Dynamodb,
            "ec2" => ServiceNamespace::Ec2,
            "ecs" => ServiceNamespace::Ecs,
            "elasticache" => ServiceNamespace::Elasticache,
            "elasticmapreduce" => ServiceNamespace::Emr,
            "kafka" => ServiceNamespace::Kafka,
            "lambda" => ServiceNamespace::Lambda,
            "neptune" => ServiceNamespace::Neptune,
            "rds" => ServiceNamespace::Rds,
            "sagemaker" => ServiceNamespace::Sagemaker,
            "workspaces" => ServiceNamespace::Workspaces,
            other => ServiceNamespace::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ServiceNamespace {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ServiceNamespace::from(s))
    }
}
impl ServiceNamespace {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ServiceNamespace::Appstream => "appstream",
            ServiceNamespace::Cassandra => "cassandra",
            ServiceNamespace::Comprehend => "comprehend",
            ServiceNamespace::CustomResource => "custom-resource",
            ServiceNamespace::Dynamodb => "dynamodb",
            ServiceNamespace::Ec2 => "ec2",
            ServiceNamespace::Ecs => "ecs",
            ServiceNamespace::Elasticache => "elasticache",
            ServiceNamespace::Emr => "elasticmapreduce",
            ServiceNamespace::Kafka => "kafka",
            ServiceNamespace::Lambda => "lambda",
            ServiceNamespace::Neptune => "neptune",
            ServiceNamespace::Rds => "rds",
            ServiceNamespace::Sagemaker => "sagemaker",
            ServiceNamespace::Workspaces => "workspaces",
            ServiceNamespace::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "appstream",
            "cassandra",
            "comprehend",
            "custom-resource",
            "dynamodb",
            "ec2",
            "ecs",
            "elasticache",
            "elasticmapreduce",
            "kafka",
            "lambda",
            "neptune",
            "rds",
            "sagemaker",
            "workspaces",
        ]
    }
}
impl ::std::convert::AsRef<str> for ServiceNamespace {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ServiceNamespace {
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
impl ::std::fmt::Display for ServiceNamespace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ServiceNamespace::Appstream => write!(f, "appstream"),
            ServiceNamespace::Cassandra => write!(f, "cassandra"),
            ServiceNamespace::Comprehend => write!(f, "comprehend"),
            ServiceNamespace::CustomResource => write!(f, "custom-resource"),
            ServiceNamespace::Dynamodb => write!(f, "dynamodb"),
            ServiceNamespace::Ec2 => write!(f, "ec2"),
            ServiceNamespace::Ecs => write!(f, "ecs"),
            ServiceNamespace::Elasticache => write!(f, "elasticache"),
            ServiceNamespace::Emr => write!(f, "elasticmapreduce"),
            ServiceNamespace::Kafka => write!(f, "kafka"),
            ServiceNamespace::Lambda => write!(f, "lambda"),
            ServiceNamespace::Neptune => write!(f, "neptune"),
            ServiceNamespace::Rds => write!(f, "rds"),
            ServiceNamespace::Sagemaker => write!(f, "sagemaker"),
            ServiceNamespace::Workspaces => write!(f, "workspaces"),
            ServiceNamespace::Unknown(value) => write!(f, "{}", value),
        }
    }
}
