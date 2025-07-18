// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The OAuth2 client app used for the connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OAuth2ClientApplication {
    /// <p>The client application clientID if the ClientAppType is <code>USER_MANAGED</code>.</p>
    pub user_managed_client_application_client_id: ::std::option::Option<::std::string::String>,
    /// <p>The reference to the SaaS-side client app that is Amazon Web Services managed.</p>
    pub aws_managed_client_application_reference: ::std::option::Option<::std::string::String>,
}
impl OAuth2ClientApplication {
    /// <p>The client application clientID if the ClientAppType is <code>USER_MANAGED</code>.</p>
    pub fn user_managed_client_application_client_id(&self) -> ::std::option::Option<&str> {
        self.user_managed_client_application_client_id.as_deref()
    }
    /// <p>The reference to the SaaS-side client app that is Amazon Web Services managed.</p>
    pub fn aws_managed_client_application_reference(&self) -> ::std::option::Option<&str> {
        self.aws_managed_client_application_reference.as_deref()
    }
}
impl OAuth2ClientApplication {
    /// Creates a new builder-style object to manufacture [`OAuth2ClientApplication`](crate::types::OAuth2ClientApplication).
    pub fn builder() -> crate::types::builders::OAuth2ClientApplicationBuilder {
        crate::types::builders::OAuth2ClientApplicationBuilder::default()
    }
}

/// A builder for [`OAuth2ClientApplication`](crate::types::OAuth2ClientApplication).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OAuth2ClientApplicationBuilder {
    pub(crate) user_managed_client_application_client_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_managed_client_application_reference: ::std::option::Option<::std::string::String>,
}
impl OAuth2ClientApplicationBuilder {
    /// <p>The client application clientID if the ClientAppType is <code>USER_MANAGED</code>.</p>
    pub fn user_managed_client_application_client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_managed_client_application_client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client application clientID if the ClientAppType is <code>USER_MANAGED</code>.</p>
    pub fn set_user_managed_client_application_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_managed_client_application_client_id = input;
        self
    }
    /// <p>The client application clientID if the ClientAppType is <code>USER_MANAGED</code>.</p>
    pub fn get_user_managed_client_application_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_managed_client_application_client_id
    }
    /// <p>The reference to the SaaS-side client app that is Amazon Web Services managed.</p>
    pub fn aws_managed_client_application_reference(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_managed_client_application_reference = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reference to the SaaS-side client app that is Amazon Web Services managed.</p>
    pub fn set_aws_managed_client_application_reference(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_managed_client_application_reference = input;
        self
    }
    /// <p>The reference to the SaaS-side client app that is Amazon Web Services managed.</p>
    pub fn get_aws_managed_client_application_reference(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_managed_client_application_reference
    }
    /// Consumes the builder and constructs a [`OAuth2ClientApplication`](crate::types::OAuth2ClientApplication).
    pub fn build(self) -> crate::types::OAuth2ClientApplication {
        crate::types::OAuth2ClientApplication {
            user_managed_client_application_client_id: self.user_managed_client_application_client_id,
            aws_managed_client_application_reference: self.aws_managed_client_application_reference,
        }
    }
}
