// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcePoliciesInput {
    /// <p>The Amazon Resource Name (ARN) of the response plan with the attached resource policy.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of resource policies to display for each page of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token for the next set of items to return. (You received this token from a previous call.)</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetResourcePoliciesInput {
    /// <p>The Amazon Resource Name (ARN) of the response plan with the attached resource policy.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The maximum number of resource policies to display for each page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetResourcePoliciesInput {
    /// Creates a new builder-style object to manufacture [`GetResourcePoliciesInput`](crate::operation::get_resource_policies::GetResourcePoliciesInput).
    pub fn builder() -> crate::operation::get_resource_policies::builders::GetResourcePoliciesInputBuilder {
        crate::operation::get_resource_policies::builders::GetResourcePoliciesInputBuilder::default()
    }
}

/// A builder for [`GetResourcePoliciesInput`](crate::operation::get_resource_policies::GetResourcePoliciesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcePoliciesInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetResourcePoliciesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the response plan with the attached resource policy.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the response plan with the attached resource policy.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the response plan with the attached resource policy.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The maximum number of resource policies to display for each page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of resource policies to display for each page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of resource policies to display for each page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetResourcePoliciesInput`](crate::operation::get_resource_policies::GetResourcePoliciesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resource_policies::GetResourcePoliciesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_resource_policies::GetResourcePoliciesInput {
            resource_arn: self.resource_arn,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
