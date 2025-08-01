// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ScalingMetricType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let scalingmetrictype = unimplemented!();
/// match scalingmetrictype {
///     ScalingMetricType::AlbRequestCountPerTarget => { /* ... */ },
///     ScalingMetricType::AsgAverageCpuUtilization => { /* ... */ },
///     ScalingMetricType::AsgAverageNetworkIn => { /* ... */ },
///     ScalingMetricType::AsgAverageNetworkOut => { /* ... */ },
///     ScalingMetricType::DynamoDbReadCapacityUtilization => { /* ... */ },
///     ScalingMetricType::DynamoDbWriteCapacityUtilization => { /* ... */ },
///     ScalingMetricType::Ec2SpotFleetRequestAverageCpuUtilization => { /* ... */ },
///     ScalingMetricType::Ec2SpotFleetRequestAverageNetworkIn => { /* ... */ },
///     ScalingMetricType::Ec2SpotFleetRequestAverageNetworkOut => { /* ... */ },
///     ScalingMetricType::EcsServiceAverageCpuUtilization => { /* ... */ },
///     ScalingMetricType::EcsServiceAverageMemoryUtilization => { /* ... */ },
///     ScalingMetricType::RdsReaderAverageCpuUtilization => { /* ... */ },
///     ScalingMetricType::RdsReaderAverageDatabaseConnections => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `scalingmetrictype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ScalingMetricType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ScalingMetricType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ScalingMetricType::NewFeature` is defined.
/// Specifically, when `scalingmetrictype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ScalingMetricType::NewFeature` also yielding `"NewFeature"`.
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
pub enum ScalingMetricType {
    #[allow(missing_docs)] // documentation missing in model
    AlbRequestCountPerTarget,
    #[allow(missing_docs)] // documentation missing in model
    AsgAverageCpuUtilization,
    #[allow(missing_docs)] // documentation missing in model
    AsgAverageNetworkIn,
    #[allow(missing_docs)] // documentation missing in model
    AsgAverageNetworkOut,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbReadCapacityUtilization,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbWriteCapacityUtilization,
    #[allow(missing_docs)] // documentation missing in model
    Ec2SpotFleetRequestAverageCpuUtilization,
    #[allow(missing_docs)] // documentation missing in model
    Ec2SpotFleetRequestAverageNetworkIn,
    #[allow(missing_docs)] // documentation missing in model
    Ec2SpotFleetRequestAverageNetworkOut,
    #[allow(missing_docs)] // documentation missing in model
    EcsServiceAverageCpuUtilization,
    #[allow(missing_docs)] // documentation missing in model
    EcsServiceAverageMemoryUtilization,
    #[allow(missing_docs)] // documentation missing in model
    RdsReaderAverageCpuUtilization,
    #[allow(missing_docs)] // documentation missing in model
    RdsReaderAverageDatabaseConnections,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ScalingMetricType {
    fn from(s: &str) -> Self {
        match s {
            "ALBRequestCountPerTarget" => ScalingMetricType::AlbRequestCountPerTarget,
            "ASGAverageCPUUtilization" => ScalingMetricType::AsgAverageCpuUtilization,
            "ASGAverageNetworkIn" => ScalingMetricType::AsgAverageNetworkIn,
            "ASGAverageNetworkOut" => ScalingMetricType::AsgAverageNetworkOut,
            "DynamoDBReadCapacityUtilization" => ScalingMetricType::DynamoDbReadCapacityUtilization,
            "DynamoDBWriteCapacityUtilization" => ScalingMetricType::DynamoDbWriteCapacityUtilization,
            "EC2SpotFleetRequestAverageCPUUtilization" => ScalingMetricType::Ec2SpotFleetRequestAverageCpuUtilization,
            "EC2SpotFleetRequestAverageNetworkIn" => ScalingMetricType::Ec2SpotFleetRequestAverageNetworkIn,
            "EC2SpotFleetRequestAverageNetworkOut" => ScalingMetricType::Ec2SpotFleetRequestAverageNetworkOut,
            "ECSServiceAverageCPUUtilization" => ScalingMetricType::EcsServiceAverageCpuUtilization,
            "ECSServiceAverageMemoryUtilization" => ScalingMetricType::EcsServiceAverageMemoryUtilization,
            "RDSReaderAverageCPUUtilization" => ScalingMetricType::RdsReaderAverageCpuUtilization,
            "RDSReaderAverageDatabaseConnections" => ScalingMetricType::RdsReaderAverageDatabaseConnections,
            other => ScalingMetricType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ScalingMetricType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ScalingMetricType::from(s))
    }
}
impl ScalingMetricType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ScalingMetricType::AlbRequestCountPerTarget => "ALBRequestCountPerTarget",
            ScalingMetricType::AsgAverageCpuUtilization => "ASGAverageCPUUtilization",
            ScalingMetricType::AsgAverageNetworkIn => "ASGAverageNetworkIn",
            ScalingMetricType::AsgAverageNetworkOut => "ASGAverageNetworkOut",
            ScalingMetricType::DynamoDbReadCapacityUtilization => "DynamoDBReadCapacityUtilization",
            ScalingMetricType::DynamoDbWriteCapacityUtilization => "DynamoDBWriteCapacityUtilization",
            ScalingMetricType::Ec2SpotFleetRequestAverageCpuUtilization => "EC2SpotFleetRequestAverageCPUUtilization",
            ScalingMetricType::Ec2SpotFleetRequestAverageNetworkIn => "EC2SpotFleetRequestAverageNetworkIn",
            ScalingMetricType::Ec2SpotFleetRequestAverageNetworkOut => "EC2SpotFleetRequestAverageNetworkOut",
            ScalingMetricType::EcsServiceAverageCpuUtilization => "ECSServiceAverageCPUUtilization",
            ScalingMetricType::EcsServiceAverageMemoryUtilization => "ECSServiceAverageMemoryUtilization",
            ScalingMetricType::RdsReaderAverageCpuUtilization => "RDSReaderAverageCPUUtilization",
            ScalingMetricType::RdsReaderAverageDatabaseConnections => "RDSReaderAverageDatabaseConnections",
            ScalingMetricType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ALBRequestCountPerTarget",
            "ASGAverageCPUUtilization",
            "ASGAverageNetworkIn",
            "ASGAverageNetworkOut",
            "DynamoDBReadCapacityUtilization",
            "DynamoDBWriteCapacityUtilization",
            "EC2SpotFleetRequestAverageCPUUtilization",
            "EC2SpotFleetRequestAverageNetworkIn",
            "EC2SpotFleetRequestAverageNetworkOut",
            "ECSServiceAverageCPUUtilization",
            "ECSServiceAverageMemoryUtilization",
            "RDSReaderAverageCPUUtilization",
            "RDSReaderAverageDatabaseConnections",
        ]
    }
}
impl ::std::convert::AsRef<str> for ScalingMetricType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ScalingMetricType {
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
impl ::std::fmt::Display for ScalingMetricType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ScalingMetricType::AlbRequestCountPerTarget => write!(f, "ALBRequestCountPerTarget"),
            ScalingMetricType::AsgAverageCpuUtilization => write!(f, "ASGAverageCPUUtilization"),
            ScalingMetricType::AsgAverageNetworkIn => write!(f, "ASGAverageNetworkIn"),
            ScalingMetricType::AsgAverageNetworkOut => write!(f, "ASGAverageNetworkOut"),
            ScalingMetricType::DynamoDbReadCapacityUtilization => write!(f, "DynamoDBReadCapacityUtilization"),
            ScalingMetricType::DynamoDbWriteCapacityUtilization => write!(f, "DynamoDBWriteCapacityUtilization"),
            ScalingMetricType::Ec2SpotFleetRequestAverageCpuUtilization => write!(f, "EC2SpotFleetRequestAverageCPUUtilization"),
            ScalingMetricType::Ec2SpotFleetRequestAverageNetworkIn => write!(f, "EC2SpotFleetRequestAverageNetworkIn"),
            ScalingMetricType::Ec2SpotFleetRequestAverageNetworkOut => write!(f, "EC2SpotFleetRequestAverageNetworkOut"),
            ScalingMetricType::EcsServiceAverageCpuUtilization => write!(f, "ECSServiceAverageCPUUtilization"),
            ScalingMetricType::EcsServiceAverageMemoryUtilization => write!(f, "ECSServiceAverageMemoryUtilization"),
            ScalingMetricType::RdsReaderAverageCpuUtilization => write!(f, "RDSReaderAverageCPUUtilization"),
            ScalingMetricType::RdsReaderAverageDatabaseConnections => write!(f, "RDSReaderAverageDatabaseConnections"),
            ScalingMetricType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
