// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStatementInput {
    /// <p>The identifier of the SQL statement to describe. This value is a universally unique identifier (UUID) generated by Amazon Redshift Data API. A suffix indicates the number of the SQL statement. For example, <code>d9b6c0c9-0747-4bf4-b142-e8883122f766:2</code> has a suffix of <code>:2</code> that indicates the second SQL statement of a batch query. This identifier is returned by <code>BatchExecuteStatment</code>, <code>ExecuteStatement</code>, and <code>ListStatements</code>.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl DescribeStatementInput {
    /// <p>The identifier of the SQL statement to describe. This value is a universally unique identifier (UUID) generated by Amazon Redshift Data API. A suffix indicates the number of the SQL statement. For example, <code>d9b6c0c9-0747-4bf4-b142-e8883122f766:2</code> has a suffix of <code>:2</code> that indicates the second SQL statement of a batch query. This identifier is returned by <code>BatchExecuteStatment</code>, <code>ExecuteStatement</code>, and <code>ListStatements</code>.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DescribeStatementInput {
    /// Creates a new builder-style object to manufacture [`DescribeStatementInput`](crate::operation::describe_statement::DescribeStatementInput).
    pub fn builder() -> crate::operation::describe_statement::builders::DescribeStatementInputBuilder {
        crate::operation::describe_statement::builders::DescribeStatementInputBuilder::default()
    }
}

/// A builder for [`DescribeStatementInput`](crate::operation::describe_statement::DescribeStatementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStatementInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DescribeStatementInputBuilder {
    /// <p>The identifier of the SQL statement to describe. This value is a universally unique identifier (UUID) generated by Amazon Redshift Data API. A suffix indicates the number of the SQL statement. For example, <code>d9b6c0c9-0747-4bf4-b142-e8883122f766:2</code> has a suffix of <code>:2</code> that indicates the second SQL statement of a batch query. This identifier is returned by <code>BatchExecuteStatment</code>, <code>ExecuteStatement</code>, and <code>ListStatements</code>.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the SQL statement to describe. This value is a universally unique identifier (UUID) generated by Amazon Redshift Data API. A suffix indicates the number of the SQL statement. For example, <code>d9b6c0c9-0747-4bf4-b142-e8883122f766:2</code> has a suffix of <code>:2</code> that indicates the second SQL statement of a batch query. This identifier is returned by <code>BatchExecuteStatment</code>, <code>ExecuteStatement</code>, and <code>ListStatements</code>.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the SQL statement to describe. This value is a universally unique identifier (UUID) generated by Amazon Redshift Data API. A suffix indicates the number of the SQL statement. For example, <code>d9b6c0c9-0747-4bf4-b142-e8883122f766:2</code> has a suffix of <code>:2</code> that indicates the second SQL statement of a batch query. This identifier is returned by <code>BatchExecuteStatment</code>, <code>ExecuteStatement</code>, and <code>ListStatements</code>.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DescribeStatementInput`](crate::operation::describe_statement::DescribeStatementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_statement::DescribeStatementInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_statement::DescribeStatementInput { id: self.id })
    }
}
