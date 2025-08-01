// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveClientIdFromOpenIdConnectProviderInput {
    /// <p>The Amazon Resource Name (ARN) of the IAM OIDC provider resource to remove the client ID from. You can get a list of OIDC provider ARNs by using the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html">ListOpenIDConnectProviders</a> operation.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub open_id_connect_provider_arn: ::std::option::Option<::std::string::String>,
    /// <p>The client ID (also known as audience) to remove from the IAM OIDC provider resource. For more information about client IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html">CreateOpenIDConnectProvider</a>.</p>
    pub client_id: ::std::option::Option<::std::string::String>,
}
impl RemoveClientIdFromOpenIdConnectProviderInput {
    /// <p>The Amazon Resource Name (ARN) of the IAM OIDC provider resource to remove the client ID from. You can get a list of OIDC provider ARNs by using the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html">ListOpenIDConnectProviders</a> operation.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn open_id_connect_provider_arn(&self) -> ::std::option::Option<&str> {
        self.open_id_connect_provider_arn.as_deref()
    }
    /// <p>The client ID (also known as audience) to remove from the IAM OIDC provider resource. For more information about client IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html">CreateOpenIDConnectProvider</a>.</p>
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }
}
impl RemoveClientIdFromOpenIdConnectProviderInput {
    /// Creates a new builder-style object to manufacture [`RemoveClientIdFromOpenIdConnectProviderInput`](crate::operation::remove_client_id_from_open_id_connect_provider::RemoveClientIdFromOpenIdConnectProviderInput).
    pub fn builder() -> crate::operation::remove_client_id_from_open_id_connect_provider::builders::RemoveClientIdFromOpenIdConnectProviderInputBuilder
    {
        crate::operation::remove_client_id_from_open_id_connect_provider::builders::RemoveClientIdFromOpenIdConnectProviderInputBuilder::default()
    }
}

/// A builder for [`RemoveClientIdFromOpenIdConnectProviderInput`](crate::operation::remove_client_id_from_open_id_connect_provider::RemoveClientIdFromOpenIdConnectProviderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveClientIdFromOpenIdConnectProviderInputBuilder {
    pub(crate) open_id_connect_provider_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
}
impl RemoveClientIdFromOpenIdConnectProviderInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the IAM OIDC provider resource to remove the client ID from. You can get a list of OIDC provider ARNs by using the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html">ListOpenIDConnectProviders</a> operation.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn open_id_connect_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.open_id_connect_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM OIDC provider resource to remove the client ID from. You can get a list of OIDC provider ARNs by using the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html">ListOpenIDConnectProviders</a> operation.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_open_id_connect_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.open_id_connect_provider_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM OIDC provider resource to remove the client ID from. You can get a list of OIDC provider ARNs by using the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html">ListOpenIDConnectProviders</a> operation.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_open_id_connect_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.open_id_connect_provider_arn
    }
    /// <p>The client ID (also known as audience) to remove from the IAM OIDC provider resource. For more information about client IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html">CreateOpenIDConnectProvider</a>.</p>
    /// This field is required.
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client ID (also known as audience) to remove from the IAM OIDC provider resource. For more information about client IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html">CreateOpenIDConnectProvider</a>.</p>
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }
    /// <p>The client ID (also known as audience) to remove from the IAM OIDC provider resource. For more information about client IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html">CreateOpenIDConnectProvider</a>.</p>
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }
    /// Consumes the builder and constructs a [`RemoveClientIdFromOpenIdConnectProviderInput`](crate::operation::remove_client_id_from_open_id_connect_provider::RemoveClientIdFromOpenIdConnectProviderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::remove_client_id_from_open_id_connect_provider::RemoveClientIdFromOpenIdConnectProviderInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::remove_client_id_from_open_id_connect_provider::RemoveClientIdFromOpenIdConnectProviderInput {
                open_id_connect_provider_arn: self.open_id_connect_provider_arn,
                client_id: self.client_id,
            },
        )
    }
}
