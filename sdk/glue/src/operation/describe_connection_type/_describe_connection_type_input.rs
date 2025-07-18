// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConnectionTypeInput {
    /// <p>The name of the connection type to be described.</p>
    pub connection_type: ::std::option::Option<::std::string::String>,
}
impl DescribeConnectionTypeInput {
    /// <p>The name of the connection type to be described.</p>
    pub fn connection_type(&self) -> ::std::option::Option<&str> {
        self.connection_type.as_deref()
    }
}
impl DescribeConnectionTypeInput {
    /// Creates a new builder-style object to manufacture [`DescribeConnectionTypeInput`](crate::operation::describe_connection_type::DescribeConnectionTypeInput).
    pub fn builder() -> crate::operation::describe_connection_type::builders::DescribeConnectionTypeInputBuilder {
        crate::operation::describe_connection_type::builders::DescribeConnectionTypeInputBuilder::default()
    }
}

/// A builder for [`DescribeConnectionTypeInput`](crate::operation::describe_connection_type::DescribeConnectionTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConnectionTypeInputBuilder {
    pub(crate) connection_type: ::std::option::Option<::std::string::String>,
}
impl DescribeConnectionTypeInputBuilder {
    /// <p>The name of the connection type to be described.</p>
    /// This field is required.
    pub fn connection_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connection type to be described.</p>
    pub fn set_connection_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_type = input;
        self
    }
    /// <p>The name of the connection type to be described.</p>
    pub fn get_connection_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_type
    }
    /// Consumes the builder and constructs a [`DescribeConnectionTypeInput`](crate::operation::describe_connection_type::DescribeConnectionTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_connection_type::DescribeConnectionTypeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_connection_type::DescribeConnectionTypeInput {
            connection_type: self.connection_type,
        })
    }
}
