// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCodeRepositoryInput {
    /// <p>The name of the Git repository to describe.</p>
    pub code_repository_name: ::std::option::Option<::std::string::String>,
}
impl DescribeCodeRepositoryInput {
    /// <p>The name of the Git repository to describe.</p>
    pub fn code_repository_name(&self) -> ::std::option::Option<&str> {
        self.code_repository_name.as_deref()
    }
}
impl DescribeCodeRepositoryInput {
    /// Creates a new builder-style object to manufacture [`DescribeCodeRepositoryInput`](crate::operation::describe_code_repository::DescribeCodeRepositoryInput).
    pub fn builder() -> crate::operation::describe_code_repository::builders::DescribeCodeRepositoryInputBuilder {
        crate::operation::describe_code_repository::builders::DescribeCodeRepositoryInputBuilder::default()
    }
}

/// A builder for [`DescribeCodeRepositoryInput`](crate::operation::describe_code_repository::DescribeCodeRepositoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCodeRepositoryInputBuilder {
    pub(crate) code_repository_name: ::std::option::Option<::std::string::String>,
}
impl DescribeCodeRepositoryInputBuilder {
    /// <p>The name of the Git repository to describe.</p>
    /// This field is required.
    pub fn code_repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Git repository to describe.</p>
    pub fn set_code_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_repository_name = input;
        self
    }
    /// <p>The name of the Git repository to describe.</p>
    pub fn get_code_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_repository_name
    }
    /// Consumes the builder and constructs a [`DescribeCodeRepositoryInput`](crate::operation::describe_code_repository::DescribeCodeRepositoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_code_repository::DescribeCodeRepositoryInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_code_repository::DescribeCodeRepositoryInput {
            code_repository_name: self.code_repository_name,
        })
    }
}
