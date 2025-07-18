// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains configuration information about an identity source.</p>
/// <p>This data type is a response parameter to the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetIdentitySource.html">GetIdentitySource</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ConfigurationDetail {
    /// <p>Contains configuration details of a Amazon Cognito user pool that Verified Permissions can use as a source of authenticated identities as entities. It specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a Amazon Cognito user pool, the policy store entity that you want to assign to user groups, and one or more application client IDs.</p>
    /// <p>Example: <code>"configuration":{"cognitoUserPoolConfiguration":{"userPoolArn":"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_1a2b3c4d5","clientIds": \["a1b2c3d4e5f6g7h8i9j0kalbmc"\],"groupConfiguration": {"groupEntityType": "MyCorp::Group"}}}</code></p>
    CognitoUserPoolConfiguration(crate::types::CognitoUserPoolConfigurationDetail),
    /// <p>Contains configuration details of an OpenID Connect (OIDC) identity provider, or identity source, that Verified Permissions can use to generate entities from authenticated identities. It specifies the issuer URL, token type that you want to use, and policy store entity details.</p>
    /// <p>Example:<code>"configuration":{"openIdConnectConfiguration":{"issuer":"https://auth.example.com","tokenSelection":{"accessTokenOnly":{"audiences":\["https://myapp.example.com","https://myapp2.example.com"\],"principalIdClaim":"sub"}},"entityIdPrefix":"MyOIDCProvider","groupConfiguration":{"groupClaim":"groups","groupEntityType":"MyCorp::UserGroup"}}}</code></p>
    OpenIdConnectConfiguration(crate::types::OpenIdConnectConfigurationDetail),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl ConfigurationDetail {
    /// Tries to convert the enum instance into [`CognitoUserPoolConfiguration`](crate::types::ConfigurationDetail::CognitoUserPoolConfiguration), extracting the inner [`CognitoUserPoolConfigurationDetail`](crate::types::CognitoUserPoolConfigurationDetail).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cognito_user_pool_configuration(&self) -> ::std::result::Result<&crate::types::CognitoUserPoolConfigurationDetail, &Self> {
        if let ConfigurationDetail::CognitoUserPoolConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CognitoUserPoolConfiguration`](crate::types::ConfigurationDetail::CognitoUserPoolConfiguration).
    pub fn is_cognito_user_pool_configuration(&self) -> bool {
        self.as_cognito_user_pool_configuration().is_ok()
    }
    /// Tries to convert the enum instance into [`OpenIdConnectConfiguration`](crate::types::ConfigurationDetail::OpenIdConnectConfiguration), extracting the inner [`OpenIdConnectConfigurationDetail`](crate::types::OpenIdConnectConfigurationDetail).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_open_id_connect_configuration(&self) -> ::std::result::Result<&crate::types::OpenIdConnectConfigurationDetail, &Self> {
        if let ConfigurationDetail::OpenIdConnectConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`OpenIdConnectConfiguration`](crate::types::ConfigurationDetail::OpenIdConnectConfiguration).
    pub fn is_open_id_connect_configuration(&self) -> bool {
        self.as_open_id_connect_configuration().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
