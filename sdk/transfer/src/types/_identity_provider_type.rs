// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `IdentityProviderType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let identityprovidertype = unimplemented!();
/// match identityprovidertype {
///     IdentityProviderType::ApiGateway => { /* ... */ },
///     IdentityProviderType::AwsDirectoryService => { /* ... */ },
///     IdentityProviderType::AwsLambda => { /* ... */ },
///     IdentityProviderType::ServiceManaged => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `identityprovidertype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `IdentityProviderType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `IdentityProviderType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `IdentityProviderType::NewFeature` is defined.
/// Specifically, when `identityprovidertype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `IdentityProviderType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>The mode of authentication for a server. The default value is <code>SERVICE_MANAGED</code>, which allows you to store and access user credentials within the Transfer Family service.</p> <p>Use <code>AWS_DIRECTORY_SERVICE</code> to provide access to Active Directory groups in Directory Service for Microsoft Active Directory or Microsoft Active Directory in your on-premises environment or in Amazon Web Services using AD Connector. This option also requires you to provide a Directory ID by using the <code>IdentityProviderDetails</code> parameter.</p> <p>Use the <code>API_GATEWAY</code> value to integrate with an identity provider of your choosing. The <code>API_GATEWAY</code> setting requires you to provide an Amazon API Gateway endpoint URL to call for authentication by using the <code>IdentityProviderDetails</code> parameter.</p> <p>Use the <code>AWS_LAMBDA</code> value to directly use an Lambda function as your identity provider. If you choose this value, you must specify the ARN for the Lambda function in the <code>Function</code> parameter for the <code>IdentityProviderDetails</code> data type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum IdentityProviderType {
    #[allow(missing_docs)] // documentation missing in model
    ApiGateway,
    #[allow(missing_docs)] // documentation missing in model
    AwsDirectoryService,
    #[allow(missing_docs)] // documentation missing in model
    AwsLambda,
    #[allow(missing_docs)] // documentation missing in model
    ServiceManaged,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for IdentityProviderType {
    fn from(s: &str) -> Self {
        match s {
            "API_GATEWAY" => IdentityProviderType::ApiGateway,
            "AWS_DIRECTORY_SERVICE" => IdentityProviderType::AwsDirectoryService,
            "AWS_LAMBDA" => IdentityProviderType::AwsLambda,
            "SERVICE_MANAGED" => IdentityProviderType::ServiceManaged,
            other => IdentityProviderType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for IdentityProviderType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(IdentityProviderType::from(s))
    }
}
impl IdentityProviderType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            IdentityProviderType::ApiGateway => "API_GATEWAY",
            IdentityProviderType::AwsDirectoryService => "AWS_DIRECTORY_SERVICE",
            IdentityProviderType::AwsLambda => "AWS_LAMBDA",
            IdentityProviderType::ServiceManaged => "SERVICE_MANAGED",
            IdentityProviderType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["API_GATEWAY", "AWS_DIRECTORY_SERVICE", "AWS_LAMBDA", "SERVICE_MANAGED"]
    }
}
impl ::std::convert::AsRef<str> for IdentityProviderType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl IdentityProviderType {
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
impl ::std::fmt::Display for IdentityProviderType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            IdentityProviderType::ApiGateway => write!(f, "API_GATEWAY"),
            IdentityProviderType::AwsDirectoryService => write!(f, "AWS_DIRECTORY_SERVICE"),
            IdentityProviderType::AwsLambda => write!(f, "AWS_LAMBDA"),
            IdentityProviderType::ServiceManaged => write!(f, "SERVICE_MANAGED"),
            IdentityProviderType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
