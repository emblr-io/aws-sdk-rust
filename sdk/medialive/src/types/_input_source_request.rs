// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings for for a PULL type input.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputSourceRequest {
    /// The key used to extract the password from EC2 Parameter store.
    pub password_param: ::std::option::Option<::std::string::String>,
    /// This represents the customer's source URL where stream is pulled from.
    pub url: ::std::option::Option<::std::string::String>,
    /// The username for the input source.
    pub username: ::std::option::Option<::std::string::String>,
}
impl InputSourceRequest {
    /// The key used to extract the password from EC2 Parameter store.
    pub fn password_param(&self) -> ::std::option::Option<&str> {
        self.password_param.as_deref()
    }
    /// This represents the customer's source URL where stream is pulled from.
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
    /// The username for the input source.
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
}
impl InputSourceRequest {
    /// Creates a new builder-style object to manufacture [`InputSourceRequest`](crate::types::InputSourceRequest).
    pub fn builder() -> crate::types::builders::InputSourceRequestBuilder {
        crate::types::builders::InputSourceRequestBuilder::default()
    }
}

/// A builder for [`InputSourceRequest`](crate::types::InputSourceRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputSourceRequestBuilder {
    pub(crate) password_param: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
}
impl InputSourceRequestBuilder {
    /// The key used to extract the password from EC2 Parameter store.
    pub fn password_param(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password_param = ::std::option::Option::Some(input.into());
        self
    }
    /// The key used to extract the password from EC2 Parameter store.
    pub fn set_password_param(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password_param = input;
        self
    }
    /// The key used to extract the password from EC2 Parameter store.
    pub fn get_password_param(&self) -> &::std::option::Option<::std::string::String> {
        &self.password_param
    }
    /// This represents the customer's source URL where stream is pulled from.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// This represents the customer's source URL where stream is pulled from.
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// This represents the customer's source URL where stream is pulled from.
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// The username for the input source.
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// The username for the input source.
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// The username for the input source.
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// Consumes the builder and constructs a [`InputSourceRequest`](crate::types::InputSourceRequest).
    pub fn build(self) -> crate::types::InputSourceRequest {
        crate::types::InputSourceRequest {
            password_param: self.password_param,
            url: self.url,
            username: self.username,
        }
    }
}
