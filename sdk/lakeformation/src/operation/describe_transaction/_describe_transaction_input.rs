// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTransactionInput {
    /// <p>The transaction for which to return status.</p>
    pub transaction_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTransactionInput {
    /// <p>The transaction for which to return status.</p>
    pub fn transaction_id(&self) -> ::std::option::Option<&str> {
        self.transaction_id.as_deref()
    }
}
impl DescribeTransactionInput {
    /// Creates a new builder-style object to manufacture [`DescribeTransactionInput`](crate::operation::describe_transaction::DescribeTransactionInput).
    pub fn builder() -> crate::operation::describe_transaction::builders::DescribeTransactionInputBuilder {
        crate::operation::describe_transaction::builders::DescribeTransactionInputBuilder::default()
    }
}

/// A builder for [`DescribeTransactionInput`](crate::operation::describe_transaction::DescribeTransactionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTransactionInputBuilder {
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTransactionInputBuilder {
    /// <p>The transaction for which to return status.</p>
    /// This field is required.
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction for which to return status.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>The transaction for which to return status.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    /// Consumes the builder and constructs a [`DescribeTransactionInput`](crate::operation::describe_transaction::DescribeTransactionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_transaction::DescribeTransactionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_transaction::DescribeTransactionInput {
            transaction_id: self.transaction_id,
        })
    }
}
