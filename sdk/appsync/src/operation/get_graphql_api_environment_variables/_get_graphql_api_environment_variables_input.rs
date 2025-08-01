// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGraphqlApiEnvironmentVariablesInput {
    /// <p>The ID of the API from which the environmental variable list will be retrieved.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
}
impl GetGraphqlApiEnvironmentVariablesInput {
    /// <p>The ID of the API from which the environmental variable list will be retrieved.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
}
impl GetGraphqlApiEnvironmentVariablesInput {
    /// Creates a new builder-style object to manufacture [`GetGraphqlApiEnvironmentVariablesInput`](crate::operation::get_graphql_api_environment_variables::GetGraphqlApiEnvironmentVariablesInput).
    pub fn builder() -> crate::operation::get_graphql_api_environment_variables::builders::GetGraphqlApiEnvironmentVariablesInputBuilder {
        crate::operation::get_graphql_api_environment_variables::builders::GetGraphqlApiEnvironmentVariablesInputBuilder::default()
    }
}

/// A builder for [`GetGraphqlApiEnvironmentVariablesInput`](crate::operation::get_graphql_api_environment_variables::GetGraphqlApiEnvironmentVariablesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGraphqlApiEnvironmentVariablesInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
}
impl GetGraphqlApiEnvironmentVariablesInputBuilder {
    /// <p>The ID of the API from which the environmental variable list will be retrieved.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the API from which the environmental variable list will be retrieved.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The ID of the API from which the environmental variable list will be retrieved.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// Consumes the builder and constructs a [`GetGraphqlApiEnvironmentVariablesInput`](crate::operation::get_graphql_api_environment_variables::GetGraphqlApiEnvironmentVariablesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_graphql_api_environment_variables::GetGraphqlApiEnvironmentVariablesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_graphql_api_environment_variables::GetGraphqlApiEnvironmentVariablesInput { api_id: self.api_id },
        )
    }
}
