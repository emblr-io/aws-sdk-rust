// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAuthorizerInput {
    /// <p>The name of the authorizer to describe.</p>
    pub authorizer_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAuthorizerInput {
    /// <p>The name of the authorizer to describe.</p>
    pub fn authorizer_name(&self) -> ::std::option::Option<&str> {
        self.authorizer_name.as_deref()
    }
}
impl DescribeAuthorizerInput {
    /// Creates a new builder-style object to manufacture [`DescribeAuthorizerInput`](crate::operation::describe_authorizer::DescribeAuthorizerInput).
    pub fn builder() -> crate::operation::describe_authorizer::builders::DescribeAuthorizerInputBuilder {
        crate::operation::describe_authorizer::builders::DescribeAuthorizerInputBuilder::default()
    }
}

/// A builder for [`DescribeAuthorizerInput`](crate::operation::describe_authorizer::DescribeAuthorizerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAuthorizerInputBuilder {
    pub(crate) authorizer_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAuthorizerInputBuilder {
    /// <p>The name of the authorizer to describe.</p>
    /// This field is required.
    pub fn authorizer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorizer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the authorizer to describe.</p>
    pub fn set_authorizer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorizer_name = input;
        self
    }
    /// <p>The name of the authorizer to describe.</p>
    pub fn get_authorizer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorizer_name
    }
    /// Consumes the builder and constructs a [`DescribeAuthorizerInput`](crate::operation::describe_authorizer::DescribeAuthorizerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_authorizer::DescribeAuthorizerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_authorizer::DescribeAuthorizerInput {
            authorizer_name: self.authorizer_name,
        })
    }
}
