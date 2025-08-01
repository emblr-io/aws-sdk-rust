// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateUserInput {
    /// <p>The user name from the Active Directory identity provider for the user.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the EC2 instance which provides user-based subscriptions.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>An object that specifies details for the Active Directory identity provider.</p>
    pub identity_provider: ::std::option::Option<crate::types::IdentityProvider>,
    /// <p>The Amazon Resource Name (ARN) of the user to disassociate from the EC2 instance.</p>
    pub instance_user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The domain name of the Active Directory that contains information for the user to disassociate.</p>
    pub domain: ::std::option::Option<::std::string::String>,
}
impl DisassociateUserInput {
    /// <p>The user name from the Active Directory identity provider for the user.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>The ID of the EC2 instance which provides user-based subscriptions.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>An object that specifies details for the Active Directory identity provider.</p>
    pub fn identity_provider(&self) -> ::std::option::Option<&crate::types::IdentityProvider> {
        self.identity_provider.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the user to disassociate from the EC2 instance.</p>
    pub fn instance_user_arn(&self) -> ::std::option::Option<&str> {
        self.instance_user_arn.as_deref()
    }
    /// <p>The domain name of the Active Directory that contains information for the user to disassociate.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
}
impl DisassociateUserInput {
    /// Creates a new builder-style object to manufacture [`DisassociateUserInput`](crate::operation::disassociate_user::DisassociateUserInput).
    pub fn builder() -> crate::operation::disassociate_user::builders::DisassociateUserInputBuilder {
        crate::operation::disassociate_user::builders::DisassociateUserInputBuilder::default()
    }
}

/// A builder for [`DisassociateUserInput`](crate::operation::disassociate_user::DisassociateUserInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateUserInputBuilder {
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_provider: ::std::option::Option<crate::types::IdentityProvider>,
    pub(crate) instance_user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) domain: ::std::option::Option<::std::string::String>,
}
impl DisassociateUserInputBuilder {
    /// <p>The user name from the Active Directory identity provider for the user.</p>
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user name from the Active Directory identity provider for the user.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The user name from the Active Directory identity provider for the user.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>The ID of the EC2 instance which provides user-based subscriptions.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the EC2 instance which provides user-based subscriptions.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the EC2 instance which provides user-based subscriptions.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>An object that specifies details for the Active Directory identity provider.</p>
    pub fn identity_provider(mut self, input: crate::types::IdentityProvider) -> Self {
        self.identity_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that specifies details for the Active Directory identity provider.</p>
    pub fn set_identity_provider(mut self, input: ::std::option::Option<crate::types::IdentityProvider>) -> Self {
        self.identity_provider = input;
        self
    }
    /// <p>An object that specifies details for the Active Directory identity provider.</p>
    pub fn get_identity_provider(&self) -> &::std::option::Option<crate::types::IdentityProvider> {
        &self.identity_provider
    }
    /// <p>The Amazon Resource Name (ARN) of the user to disassociate from the EC2 instance.</p>
    pub fn instance_user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user to disassociate from the EC2 instance.</p>
    pub fn set_instance_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user to disassociate from the EC2 instance.</p>
    pub fn get_instance_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_user_arn
    }
    /// <p>The domain name of the Active Directory that contains information for the user to disassociate.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name of the Active Directory that contains information for the user to disassociate.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The domain name of the Active Directory that contains information for the user to disassociate.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Consumes the builder and constructs a [`DisassociateUserInput`](crate::operation::disassociate_user::DisassociateUserInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disassociate_user::DisassociateUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::disassociate_user::DisassociateUserInput {
            username: self.username,
            instance_id: self.instance_id,
            identity_provider: self.identity_provider,
            instance_user_arn: self.instance_user_arn,
            domain: self.domain,
        })
    }
}
