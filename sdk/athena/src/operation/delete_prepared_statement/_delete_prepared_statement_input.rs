// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePreparedStatementInput {
    /// <p>The name of the prepared statement to delete.</p>
    pub statement_name: ::std::option::Option<::std::string::String>,
    /// <p>The workgroup to which the statement to be deleted belongs.</p>
    pub work_group: ::std::option::Option<::std::string::String>,
}
impl DeletePreparedStatementInput {
    /// <p>The name of the prepared statement to delete.</p>
    pub fn statement_name(&self) -> ::std::option::Option<&str> {
        self.statement_name.as_deref()
    }
    /// <p>The workgroup to which the statement to be deleted belongs.</p>
    pub fn work_group(&self) -> ::std::option::Option<&str> {
        self.work_group.as_deref()
    }
}
impl DeletePreparedStatementInput {
    /// Creates a new builder-style object to manufacture [`DeletePreparedStatementInput`](crate::operation::delete_prepared_statement::DeletePreparedStatementInput).
    pub fn builder() -> crate::operation::delete_prepared_statement::builders::DeletePreparedStatementInputBuilder {
        crate::operation::delete_prepared_statement::builders::DeletePreparedStatementInputBuilder::default()
    }
}

/// A builder for [`DeletePreparedStatementInput`](crate::operation::delete_prepared_statement::DeletePreparedStatementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePreparedStatementInputBuilder {
    pub(crate) statement_name: ::std::option::Option<::std::string::String>,
    pub(crate) work_group: ::std::option::Option<::std::string::String>,
}
impl DeletePreparedStatementInputBuilder {
    /// <p>The name of the prepared statement to delete.</p>
    /// This field is required.
    pub fn statement_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the prepared statement to delete.</p>
    pub fn set_statement_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_name = input;
        self
    }
    /// <p>The name of the prepared statement to delete.</p>
    pub fn get_statement_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_name
    }
    /// <p>The workgroup to which the statement to be deleted belongs.</p>
    /// This field is required.
    pub fn work_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.work_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The workgroup to which the statement to be deleted belongs.</p>
    pub fn set_work_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.work_group = input;
        self
    }
    /// <p>The workgroup to which the statement to be deleted belongs.</p>
    pub fn get_work_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.work_group
    }
    /// Consumes the builder and constructs a [`DeletePreparedStatementInput`](crate::operation::delete_prepared_statement::DeletePreparedStatementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_prepared_statement::DeletePreparedStatementInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_prepared_statement::DeletePreparedStatementInput {
            statement_name: self.statement_name,
            work_group: self.work_group,
        })
    }
}
