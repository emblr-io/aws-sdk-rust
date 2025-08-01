// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `LayerType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let layertype = unimplemented!();
/// match layertype {
///     LayerType::AwsFlowRuby => { /* ... */ },
///     LayerType::Custom => { /* ... */ },
///     LayerType::DbMaster => { /* ... */ },
///     LayerType::EcsCluster => { /* ... */ },
///     LayerType::JavaApp => { /* ... */ },
///     LayerType::Lb => { /* ... */ },
///     LayerType::Memcached => { /* ... */ },
///     LayerType::MonitoringMaster => { /* ... */ },
///     LayerType::NodejsApp => { /* ... */ },
///     LayerType::PhpApp => { /* ... */ },
///     LayerType::RailsApp => { /* ... */ },
///     LayerType::Web => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `layertype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `LayerType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `LayerType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `LayerType::NewFeature` is defined.
/// Specifically, when `layertype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `LayerType::NewFeature` also yielding `"NewFeature"`.
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
pub enum LayerType {
    #[allow(missing_docs)] // documentation missing in model
    AwsFlowRuby,
    #[allow(missing_docs)] // documentation missing in model
    Custom,
    #[allow(missing_docs)] // documentation missing in model
    DbMaster,
    #[allow(missing_docs)] // documentation missing in model
    EcsCluster,
    #[allow(missing_docs)] // documentation missing in model
    JavaApp,
    #[allow(missing_docs)] // documentation missing in model
    Lb,
    #[allow(missing_docs)] // documentation missing in model
    Memcached,
    #[allow(missing_docs)] // documentation missing in model
    MonitoringMaster,
    #[allow(missing_docs)] // documentation missing in model
    NodejsApp,
    #[allow(missing_docs)] // documentation missing in model
    PhpApp,
    #[allow(missing_docs)] // documentation missing in model
    RailsApp,
    #[allow(missing_docs)] // documentation missing in model
    Web,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for LayerType {
    fn from(s: &str) -> Self {
        match s {
            "aws-flow-ruby" => LayerType::AwsFlowRuby,
            "custom" => LayerType::Custom,
            "db-master" => LayerType::DbMaster,
            "ecs-cluster" => LayerType::EcsCluster,
            "java-app" => LayerType::JavaApp,
            "lb" => LayerType::Lb,
            "memcached" => LayerType::Memcached,
            "monitoring-master" => LayerType::MonitoringMaster,
            "nodejs-app" => LayerType::NodejsApp,
            "php-app" => LayerType::PhpApp,
            "rails-app" => LayerType::RailsApp,
            "web" => LayerType::Web,
            other => LayerType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for LayerType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(LayerType::from(s))
    }
}
impl LayerType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            LayerType::AwsFlowRuby => "aws-flow-ruby",
            LayerType::Custom => "custom",
            LayerType::DbMaster => "db-master",
            LayerType::EcsCluster => "ecs-cluster",
            LayerType::JavaApp => "java-app",
            LayerType::Lb => "lb",
            LayerType::Memcached => "memcached",
            LayerType::MonitoringMaster => "monitoring-master",
            LayerType::NodejsApp => "nodejs-app",
            LayerType::PhpApp => "php-app",
            LayerType::RailsApp => "rails-app",
            LayerType::Web => "web",
            LayerType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "aws-flow-ruby",
            "custom",
            "db-master",
            "ecs-cluster",
            "java-app",
            "lb",
            "memcached",
            "monitoring-master",
            "nodejs-app",
            "php-app",
            "rails-app",
            "web",
        ]
    }
}
impl ::std::convert::AsRef<str> for LayerType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl LayerType {
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
impl ::std::fmt::Display for LayerType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            LayerType::AwsFlowRuby => write!(f, "aws-flow-ruby"),
            LayerType::Custom => write!(f, "custom"),
            LayerType::DbMaster => write!(f, "db-master"),
            LayerType::EcsCluster => write!(f, "ecs-cluster"),
            LayerType::JavaApp => write!(f, "java-app"),
            LayerType::Lb => write!(f, "lb"),
            LayerType::Memcached => write!(f, "memcached"),
            LayerType::MonitoringMaster => write!(f, "monitoring-master"),
            LayerType::NodejsApp => write!(f, "nodejs-app"),
            LayerType::PhpApp => write!(f, "php-app"),
            LayerType::RailsApp => write!(f, "rails-app"),
            LayerType::Web => write!(f, "web"),
            LayerType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
