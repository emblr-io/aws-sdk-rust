// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTagOptionInput {
    /// <p>The TagOption identifier.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl DescribeTagOptionInput {
    /// <p>The TagOption identifier.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DescribeTagOptionInput {
    /// Creates a new builder-style object to manufacture [`DescribeTagOptionInput`](crate::operation::describe_tag_option::DescribeTagOptionInput).
    pub fn builder() -> crate::operation::describe_tag_option::builders::DescribeTagOptionInputBuilder {
        crate::operation::describe_tag_option::builders::DescribeTagOptionInputBuilder::default()
    }
}

/// A builder for [`DescribeTagOptionInput`](crate::operation::describe_tag_option::DescribeTagOptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTagOptionInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DescribeTagOptionInputBuilder {
    /// <p>The TagOption identifier.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The TagOption identifier.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The TagOption identifier.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DescribeTagOptionInput`](crate::operation::describe_tag_option::DescribeTagOptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_tag_option::DescribeTagOptionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_tag_option::DescribeTagOptionInput { id: self.id })
    }
}
