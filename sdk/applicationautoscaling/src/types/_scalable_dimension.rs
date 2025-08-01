// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ScalableDimension`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let scalabledimension = unimplemented!();
/// match scalabledimension {
///     ScalableDimension::AppstreamFleetDesiredCapacity => { /* ... */ },
///     ScalableDimension::CassandraTableReadCapacityUnits => { /* ... */ },
///     ScalableDimension::CassandraTableWriteCapacityUnits => { /* ... */ },
///     ScalableDimension::ComprehendDocClassifierEndpointInferenceUnits => { /* ... */ },
///     ScalableDimension::ComprehendEntityRecognizerEndpointInferenceUnits => { /* ... */ },
///     ScalableDimension::CustomResourceScalableDimension => { /* ... */ },
///     ScalableDimension::DynamoDbIndexReadCapacityUnits => { /* ... */ },
///     ScalableDimension::DynamoDbIndexWriteCapacityUnits => { /* ... */ },
///     ScalableDimension::DynamoDbTableReadCapacityUnits => { /* ... */ },
///     ScalableDimension::DynamoDbTableWriteCapacityUnits => { /* ... */ },
///     ScalableDimension::Ec2SpotFleetRequestTargetCapacity => { /* ... */ },
///     ScalableDimension::EcsServiceDesiredCount => { /* ... */ },
///     ScalableDimension::ElastiCacheCacheClusterNodes => { /* ... */ },
///     ScalableDimension::ElastiCacheReplicationGroupNodeGroups => { /* ... */ },
///     ScalableDimension::ElastiCacheReplicationGroupReplicas => { /* ... */ },
///     ScalableDimension::EmrInstanceGroupInstanceCount => { /* ... */ },
///     ScalableDimension::KafkaBrokerStorageVolumeSize => { /* ... */ },
///     ScalableDimension::LambdaFunctionProvisionedConcurrency => { /* ... */ },
///     ScalableDimension::NeptuneClusterReadReplicaCount => { /* ... */ },
///     ScalableDimension::RdsClusterReadReplicaCount => { /* ... */ },
///     ScalableDimension::SageMakerInferenceComponentDesiredCopyCount => { /* ... */ },
///     ScalableDimension::SageMakerVariantDesiredInstanceCount => { /* ... */ },
///     ScalableDimension::SageMakerVariantDesiredProvisionedConcurrency => { /* ... */ },
///     ScalableDimension::WorkSpacesWorkSpacesPoolDesiredUserSessions => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `scalabledimension` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ScalableDimension::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ScalableDimension::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ScalableDimension::NewFeature` is defined.
/// Specifically, when `scalabledimension` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ScalableDimension::NewFeature` also yielding `"NewFeature"`.
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
pub enum ScalableDimension {
    #[allow(missing_docs)] // documentation missing in model
    AppstreamFleetDesiredCapacity,
    #[allow(missing_docs)] // documentation missing in model
    CassandraTableReadCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    CassandraTableWriteCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    ComprehendDocClassifierEndpointInferenceUnits,
    #[allow(missing_docs)] // documentation missing in model
    ComprehendEntityRecognizerEndpointInferenceUnits,
    #[allow(missing_docs)] // documentation missing in model
    CustomResourceScalableDimension,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbIndexReadCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbIndexWriteCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbTableReadCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    DynamoDbTableWriteCapacityUnits,
    #[allow(missing_docs)] // documentation missing in model
    Ec2SpotFleetRequestTargetCapacity,
    #[allow(missing_docs)] // documentation missing in model
    EcsServiceDesiredCount,
    #[allow(missing_docs)] // documentation missing in model
    ElastiCacheCacheClusterNodes,
    #[allow(missing_docs)] // documentation missing in model
    ElastiCacheReplicationGroupNodeGroups,
    #[allow(missing_docs)] // documentation missing in model
    ElastiCacheReplicationGroupReplicas,
    #[allow(missing_docs)] // documentation missing in model
    EmrInstanceGroupInstanceCount,
    #[allow(missing_docs)] // documentation missing in model
    KafkaBrokerStorageVolumeSize,
    #[allow(missing_docs)] // documentation missing in model
    LambdaFunctionProvisionedConcurrency,
    #[allow(missing_docs)] // documentation missing in model
    NeptuneClusterReadReplicaCount,
    #[allow(missing_docs)] // documentation missing in model
    RdsClusterReadReplicaCount,
    #[allow(missing_docs)] // documentation missing in model
    SageMakerInferenceComponentDesiredCopyCount,
    #[allow(missing_docs)] // documentation missing in model
    SageMakerVariantDesiredInstanceCount,
    #[allow(missing_docs)] // documentation missing in model
    SageMakerVariantDesiredProvisionedConcurrency,
    #[allow(missing_docs)] // documentation missing in model
    WorkSpacesWorkSpacesPoolDesiredUserSessions,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ScalableDimension {
    fn from(s: &str) -> Self {
        match s {
            "appstream:fleet:DesiredCapacity" => ScalableDimension::AppstreamFleetDesiredCapacity,
            "cassandra:table:ReadCapacityUnits" => ScalableDimension::CassandraTableReadCapacityUnits,
            "cassandra:table:WriteCapacityUnits" => ScalableDimension::CassandraTableWriteCapacityUnits,
            "comprehend:document-classifier-endpoint:DesiredInferenceUnits" => ScalableDimension::ComprehendDocClassifierEndpointInferenceUnits,
            "comprehend:entity-recognizer-endpoint:DesiredInferenceUnits" => ScalableDimension::ComprehendEntityRecognizerEndpointInferenceUnits,
            "custom-resource:ResourceType:Property" => ScalableDimension::CustomResourceScalableDimension,
            "dynamodb:index:ReadCapacityUnits" => ScalableDimension::DynamoDbIndexReadCapacityUnits,
            "dynamodb:index:WriteCapacityUnits" => ScalableDimension::DynamoDbIndexWriteCapacityUnits,
            "dynamodb:table:ReadCapacityUnits" => ScalableDimension::DynamoDbTableReadCapacityUnits,
            "dynamodb:table:WriteCapacityUnits" => ScalableDimension::DynamoDbTableWriteCapacityUnits,
            "ec2:spot-fleet-request:TargetCapacity" => ScalableDimension::Ec2SpotFleetRequestTargetCapacity,
            "ecs:service:DesiredCount" => ScalableDimension::EcsServiceDesiredCount,
            "elasticache:cache-cluster:Nodes" => ScalableDimension::ElastiCacheCacheClusterNodes,
            "elasticache:replication-group:NodeGroups" => ScalableDimension::ElastiCacheReplicationGroupNodeGroups,
            "elasticache:replication-group:Replicas" => ScalableDimension::ElastiCacheReplicationGroupReplicas,
            "elasticmapreduce:instancegroup:InstanceCount" => ScalableDimension::EmrInstanceGroupInstanceCount,
            "kafka:broker-storage:VolumeSize" => ScalableDimension::KafkaBrokerStorageVolumeSize,
            "lambda:function:ProvisionedConcurrency" => ScalableDimension::LambdaFunctionProvisionedConcurrency,
            "neptune:cluster:ReadReplicaCount" => ScalableDimension::NeptuneClusterReadReplicaCount,
            "rds:cluster:ReadReplicaCount" => ScalableDimension::RdsClusterReadReplicaCount,
            "sagemaker:inference-component:DesiredCopyCount" => ScalableDimension::SageMakerInferenceComponentDesiredCopyCount,
            "sagemaker:variant:DesiredInstanceCount" => ScalableDimension::SageMakerVariantDesiredInstanceCount,
            "sagemaker:variant:DesiredProvisionedConcurrency" => ScalableDimension::SageMakerVariantDesiredProvisionedConcurrency,
            "workspaces:workspacespool:DesiredUserSessions" => ScalableDimension::WorkSpacesWorkSpacesPoolDesiredUserSessions,
            other => ScalableDimension::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ScalableDimension {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ScalableDimension::from(s))
    }
}
impl ScalableDimension {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ScalableDimension::AppstreamFleetDesiredCapacity => "appstream:fleet:DesiredCapacity",
            ScalableDimension::CassandraTableReadCapacityUnits => "cassandra:table:ReadCapacityUnits",
            ScalableDimension::CassandraTableWriteCapacityUnits => "cassandra:table:WriteCapacityUnits",
            ScalableDimension::ComprehendDocClassifierEndpointInferenceUnits => "comprehend:document-classifier-endpoint:DesiredInferenceUnits",
            ScalableDimension::ComprehendEntityRecognizerEndpointInferenceUnits => "comprehend:entity-recognizer-endpoint:DesiredInferenceUnits",
            ScalableDimension::CustomResourceScalableDimension => "custom-resource:ResourceType:Property",
            ScalableDimension::DynamoDbIndexReadCapacityUnits => "dynamodb:index:ReadCapacityUnits",
            ScalableDimension::DynamoDbIndexWriteCapacityUnits => "dynamodb:index:WriteCapacityUnits",
            ScalableDimension::DynamoDbTableReadCapacityUnits => "dynamodb:table:ReadCapacityUnits",
            ScalableDimension::DynamoDbTableWriteCapacityUnits => "dynamodb:table:WriteCapacityUnits",
            ScalableDimension::Ec2SpotFleetRequestTargetCapacity => "ec2:spot-fleet-request:TargetCapacity",
            ScalableDimension::EcsServiceDesiredCount => "ecs:service:DesiredCount",
            ScalableDimension::ElastiCacheCacheClusterNodes => "elasticache:cache-cluster:Nodes",
            ScalableDimension::ElastiCacheReplicationGroupNodeGroups => "elasticache:replication-group:NodeGroups",
            ScalableDimension::ElastiCacheReplicationGroupReplicas => "elasticache:replication-group:Replicas",
            ScalableDimension::EmrInstanceGroupInstanceCount => "elasticmapreduce:instancegroup:InstanceCount",
            ScalableDimension::KafkaBrokerStorageVolumeSize => "kafka:broker-storage:VolumeSize",
            ScalableDimension::LambdaFunctionProvisionedConcurrency => "lambda:function:ProvisionedConcurrency",
            ScalableDimension::NeptuneClusterReadReplicaCount => "neptune:cluster:ReadReplicaCount",
            ScalableDimension::RdsClusterReadReplicaCount => "rds:cluster:ReadReplicaCount",
            ScalableDimension::SageMakerInferenceComponentDesiredCopyCount => "sagemaker:inference-component:DesiredCopyCount",
            ScalableDimension::SageMakerVariantDesiredInstanceCount => "sagemaker:variant:DesiredInstanceCount",
            ScalableDimension::SageMakerVariantDesiredProvisionedConcurrency => "sagemaker:variant:DesiredProvisionedConcurrency",
            ScalableDimension::WorkSpacesWorkSpacesPoolDesiredUserSessions => "workspaces:workspacespool:DesiredUserSessions",
            ScalableDimension::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "appstream:fleet:DesiredCapacity",
            "cassandra:table:ReadCapacityUnits",
            "cassandra:table:WriteCapacityUnits",
            "comprehend:document-classifier-endpoint:DesiredInferenceUnits",
            "comprehend:entity-recognizer-endpoint:DesiredInferenceUnits",
            "custom-resource:ResourceType:Property",
            "dynamodb:index:ReadCapacityUnits",
            "dynamodb:index:WriteCapacityUnits",
            "dynamodb:table:ReadCapacityUnits",
            "dynamodb:table:WriteCapacityUnits",
            "ec2:spot-fleet-request:TargetCapacity",
            "ecs:service:DesiredCount",
            "elasticache:cache-cluster:Nodes",
            "elasticache:replication-group:NodeGroups",
            "elasticache:replication-group:Replicas",
            "elasticmapreduce:instancegroup:InstanceCount",
            "kafka:broker-storage:VolumeSize",
            "lambda:function:ProvisionedConcurrency",
            "neptune:cluster:ReadReplicaCount",
            "rds:cluster:ReadReplicaCount",
            "sagemaker:inference-component:DesiredCopyCount",
            "sagemaker:variant:DesiredInstanceCount",
            "sagemaker:variant:DesiredProvisionedConcurrency",
            "workspaces:workspacespool:DesiredUserSessions",
        ]
    }
}
impl ::std::convert::AsRef<str> for ScalableDimension {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ScalableDimension {
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
impl ::std::fmt::Display for ScalableDimension {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ScalableDimension::AppstreamFleetDesiredCapacity => write!(f, "appstream:fleet:DesiredCapacity"),
            ScalableDimension::CassandraTableReadCapacityUnits => write!(f, "cassandra:table:ReadCapacityUnits"),
            ScalableDimension::CassandraTableWriteCapacityUnits => write!(f, "cassandra:table:WriteCapacityUnits"),
            ScalableDimension::ComprehendDocClassifierEndpointInferenceUnits => {
                write!(f, "comprehend:document-classifier-endpoint:DesiredInferenceUnits")
            }
            ScalableDimension::ComprehendEntityRecognizerEndpointInferenceUnits => {
                write!(f, "comprehend:entity-recognizer-endpoint:DesiredInferenceUnits")
            }
            ScalableDimension::CustomResourceScalableDimension => write!(f, "custom-resource:ResourceType:Property"),
            ScalableDimension::DynamoDbIndexReadCapacityUnits => write!(f, "dynamodb:index:ReadCapacityUnits"),
            ScalableDimension::DynamoDbIndexWriteCapacityUnits => write!(f, "dynamodb:index:WriteCapacityUnits"),
            ScalableDimension::DynamoDbTableReadCapacityUnits => write!(f, "dynamodb:table:ReadCapacityUnits"),
            ScalableDimension::DynamoDbTableWriteCapacityUnits => write!(f, "dynamodb:table:WriteCapacityUnits"),
            ScalableDimension::Ec2SpotFleetRequestTargetCapacity => write!(f, "ec2:spot-fleet-request:TargetCapacity"),
            ScalableDimension::EcsServiceDesiredCount => write!(f, "ecs:service:DesiredCount"),
            ScalableDimension::ElastiCacheCacheClusterNodes => write!(f, "elasticache:cache-cluster:Nodes"),
            ScalableDimension::ElastiCacheReplicationGroupNodeGroups => write!(f, "elasticache:replication-group:NodeGroups"),
            ScalableDimension::ElastiCacheReplicationGroupReplicas => write!(f, "elasticache:replication-group:Replicas"),
            ScalableDimension::EmrInstanceGroupInstanceCount => write!(f, "elasticmapreduce:instancegroup:InstanceCount"),
            ScalableDimension::KafkaBrokerStorageVolumeSize => write!(f, "kafka:broker-storage:VolumeSize"),
            ScalableDimension::LambdaFunctionProvisionedConcurrency => write!(f, "lambda:function:ProvisionedConcurrency"),
            ScalableDimension::NeptuneClusterReadReplicaCount => write!(f, "neptune:cluster:ReadReplicaCount"),
            ScalableDimension::RdsClusterReadReplicaCount => write!(f, "rds:cluster:ReadReplicaCount"),
            ScalableDimension::SageMakerInferenceComponentDesiredCopyCount => write!(f, "sagemaker:inference-component:DesiredCopyCount"),
            ScalableDimension::SageMakerVariantDesiredInstanceCount => write!(f, "sagemaker:variant:DesiredInstanceCount"),
            ScalableDimension::SageMakerVariantDesiredProvisionedConcurrency => write!(f, "sagemaker:variant:DesiredProvisionedConcurrency"),
            ScalableDimension::WorkSpacesWorkSpacesPoolDesiredUserSessions => write!(f, "workspaces:workspacespool:DesiredUserSessions"),
            ScalableDimension::Unknown(value) => write!(f, "{}", value),
        }
    }
}
