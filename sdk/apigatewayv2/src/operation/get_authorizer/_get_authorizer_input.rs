// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAuthorizerInput {
    /// <p>The API identifier.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The authorizer identifier.</p>
    pub authorizer_id: ::std::option::Option<::std::string::String>,
}
impl GetAuthorizerInput {
    /// <p>The API identifier.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The authorizer identifier.</p>
    pub fn authorizer_id(&self) -> ::std::option::Option<&str> {
        self.authorizer_id.as_deref()
    }
}
impl GetAuthorizerInput {
    /// Creates a new builder-style object to manufacture [`GetAuthorizerInput`](crate::operation::get_authorizer::GetAuthorizerInput).
    pub fn builder() -> crate::operation::get_authorizer::builders::GetAuthorizerInputBuilder {
        crate::operation::get_authorizer::builders::GetAuthorizerInputBuilder::default()
    }
}

/// A builder for [`GetAuthorizerInput`](crate::operation::get_authorizer::GetAuthorizerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAuthorizerInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) authorizer_id: ::std::option::Option<::std::string::String>,
}
impl GetAuthorizerInputBuilder {
    /// <p>The API identifier.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API identifier.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API identifier.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The authorizer identifier.</p>
    /// This field is required.
    pub fn authorizer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorizer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authorizer identifier.</p>
    pub fn set_authorizer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorizer_id = input;
        self
    }
    /// <p>The authorizer identifier.</p>
    pub fn get_authorizer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorizer_id
    }
    /// Consumes the builder and constructs a [`GetAuthorizerInput`](crate::operation::get_authorizer::GetAuthorizerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_authorizer::GetAuthorizerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_authorizer::GetAuthorizerInput {
            api_id: self.api_id,
            authorizer_id: self.authorizer_id,
        })
    }
}
