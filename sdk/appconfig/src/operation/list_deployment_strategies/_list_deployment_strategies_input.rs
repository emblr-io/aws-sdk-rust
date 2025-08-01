// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDeploymentStrategiesInput {
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListDeploymentStrategiesInput {
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListDeploymentStrategiesInput {
    /// Creates a new builder-style object to manufacture [`ListDeploymentStrategiesInput`](crate::operation::list_deployment_strategies::ListDeploymentStrategiesInput).
    pub fn builder() -> crate::operation::list_deployment_strategies::builders::ListDeploymentStrategiesInputBuilder {
        crate::operation::list_deployment_strategies::builders::ListDeploymentStrategiesInputBuilder::default()
    }
}

/// A builder for [`ListDeploymentStrategiesInput`](crate::operation::list_deployment_strategies::ListDeploymentStrategiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDeploymentStrategiesInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListDeploymentStrategiesInputBuilder {
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListDeploymentStrategiesInput`](crate::operation::list_deployment_strategies::ListDeploymentStrategiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_deployment_strategies::ListDeploymentStrategiesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_deployment_strategies::ListDeploymentStrategiesInput {
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
