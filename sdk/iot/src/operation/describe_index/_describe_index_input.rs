// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeIndexInput {
    /// <p>The index name.</p>
    pub index_name: ::std::option::Option<::std::string::String>,
}
impl DescribeIndexInput {
    /// <p>The index name.</p>
    pub fn index_name(&self) -> ::std::option::Option<&str> {
        self.index_name.as_deref()
    }
}
impl DescribeIndexInput {
    /// Creates a new builder-style object to manufacture [`DescribeIndexInput`](crate::operation::describe_index::DescribeIndexInput).
    pub fn builder() -> crate::operation::describe_index::builders::DescribeIndexInputBuilder {
        crate::operation::describe_index::builders::DescribeIndexInputBuilder::default()
    }
}

/// A builder for [`DescribeIndexInput`](crate::operation::describe_index::DescribeIndexInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeIndexInputBuilder {
    pub(crate) index_name: ::std::option::Option<::std::string::String>,
}
impl DescribeIndexInputBuilder {
    /// <p>The index name.</p>
    /// This field is required.
    pub fn index_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The index name.</p>
    pub fn set_index_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_name = input;
        self
    }
    /// <p>The index name.</p>
    pub fn get_index_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_name
    }
    /// Consumes the builder and constructs a [`DescribeIndexInput`](crate::operation::describe_index::DescribeIndexInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_index::DescribeIndexInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_index::DescribeIndexInput { index_name: self.index_name })
    }
}
