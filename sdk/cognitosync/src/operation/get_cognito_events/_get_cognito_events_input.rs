// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request for a list of the configured Cognito Events</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCognitoEventsInput {
    /// <p>The Cognito Identity Pool ID for the request</p>
    pub identity_pool_id: ::std::option::Option<::std::string::String>,
}
impl GetCognitoEventsInput {
    /// <p>The Cognito Identity Pool ID for the request</p>
    pub fn identity_pool_id(&self) -> ::std::option::Option<&str> {
        self.identity_pool_id.as_deref()
    }
}
impl GetCognitoEventsInput {
    /// Creates a new builder-style object to manufacture [`GetCognitoEventsInput`](crate::operation::get_cognito_events::GetCognitoEventsInput).
    pub fn builder() -> crate::operation::get_cognito_events::builders::GetCognitoEventsInputBuilder {
        crate::operation::get_cognito_events::builders::GetCognitoEventsInputBuilder::default()
    }
}

/// A builder for [`GetCognitoEventsInput`](crate::operation::get_cognito_events::GetCognitoEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCognitoEventsInputBuilder {
    pub(crate) identity_pool_id: ::std::option::Option<::std::string::String>,
}
impl GetCognitoEventsInputBuilder {
    /// <p>The Cognito Identity Pool ID for the request</p>
    /// This field is required.
    pub fn identity_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Cognito Identity Pool ID for the request</p>
    pub fn set_identity_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_pool_id = input;
        self
    }
    /// <p>The Cognito Identity Pool ID for the request</p>
    pub fn get_identity_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_pool_id
    }
    /// Consumes the builder and constructs a [`GetCognitoEventsInput`](crate::operation::get_cognito_events::GetCognitoEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_cognito_events::GetCognitoEventsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_cognito_events::GetCognitoEventsInput {
            identity_pool_id: self.identity_pool_id,
        })
    }
}
