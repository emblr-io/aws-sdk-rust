// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteTransactionInput {
    /// <p>The list of PartiQL statements representing the transaction to run.</p>
    pub transact_statements: ::std::option::Option<::std::vec::Vec<crate::types::ParameterizedStatement>>,
    /// <p>Set this value to get remaining results, if <code>NextToken</code> was returned in the statement response.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>Determines the level of detail about either provisioned or on-demand throughput consumption that is returned in the response. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html">TransactGetItems</a> and <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html">TransactWriteItems</a>.</p>
    pub return_consumed_capacity: ::std::option::Option<crate::types::ReturnConsumedCapacity>,
}
impl ExecuteTransactionInput {
    /// <p>The list of PartiQL statements representing the transaction to run.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.transact_statements.is_none()`.
    pub fn transact_statements(&self) -> &[crate::types::ParameterizedStatement] {
        self.transact_statements.as_deref().unwrap_or_default()
    }
    /// <p>Set this value to get remaining results, if <code>NextToken</code> was returned in the statement response.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>Determines the level of detail about either provisioned or on-demand throughput consumption that is returned in the response. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html">TransactGetItems</a> and <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html">TransactWriteItems</a>.</p>
    pub fn return_consumed_capacity(&self) -> ::std::option::Option<&crate::types::ReturnConsumedCapacity> {
        self.return_consumed_capacity.as_ref()
    }
}
impl ExecuteTransactionInput {
    /// Creates a new builder-style object to manufacture [`ExecuteTransactionInput`](crate::operation::execute_transaction::ExecuteTransactionInput).
    pub fn builder() -> crate::operation::execute_transaction::builders::ExecuteTransactionInputBuilder {
        crate::operation::execute_transaction::builders::ExecuteTransactionInputBuilder::default()
    }
}

/// A builder for [`ExecuteTransactionInput`](crate::operation::execute_transaction::ExecuteTransactionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteTransactionInputBuilder {
    pub(crate) transact_statements: ::std::option::Option<::std::vec::Vec<crate::types::ParameterizedStatement>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) return_consumed_capacity: ::std::option::Option<crate::types::ReturnConsumedCapacity>,
}
impl ExecuteTransactionInputBuilder {
    /// Appends an item to `transact_statements`.
    ///
    /// To override the contents of this collection use [`set_transact_statements`](Self::set_transact_statements).
    ///
    /// <p>The list of PartiQL statements representing the transaction to run.</p>
    pub fn transact_statements(mut self, input: crate::types::ParameterizedStatement) -> Self {
        let mut v = self.transact_statements.unwrap_or_default();
        v.push(input);
        self.transact_statements = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of PartiQL statements representing the transaction to run.</p>
    pub fn set_transact_statements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParameterizedStatement>>) -> Self {
        self.transact_statements = input;
        self
    }
    /// <p>The list of PartiQL statements representing the transaction to run.</p>
    pub fn get_transact_statements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParameterizedStatement>> {
        &self.transact_statements
    }
    /// <p>Set this value to get remaining results, if <code>NextToken</code> was returned in the statement response.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Set this value to get remaining results, if <code>NextToken</code> was returned in the statement response.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Set this value to get remaining results, if <code>NextToken</code> was returned in the statement response.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>Determines the level of detail about either provisioned or on-demand throughput consumption that is returned in the response. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html">TransactGetItems</a> and <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html">TransactWriteItems</a>.</p>
    pub fn return_consumed_capacity(mut self, input: crate::types::ReturnConsumedCapacity) -> Self {
        self.return_consumed_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines the level of detail about either provisioned or on-demand throughput consumption that is returned in the response. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html">TransactGetItems</a> and <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html">TransactWriteItems</a>.</p>
    pub fn set_return_consumed_capacity(mut self, input: ::std::option::Option<crate::types::ReturnConsumedCapacity>) -> Self {
        self.return_consumed_capacity = input;
        self
    }
    /// <p>Determines the level of detail about either provisioned or on-demand throughput consumption that is returned in the response. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html">TransactGetItems</a> and <a href="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html">TransactWriteItems</a>.</p>
    pub fn get_return_consumed_capacity(&self) -> &::std::option::Option<crate::types::ReturnConsumedCapacity> {
        &self.return_consumed_capacity
    }
    /// Consumes the builder and constructs a [`ExecuteTransactionInput`](crate::operation::execute_transaction::ExecuteTransactionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::execute_transaction::ExecuteTransactionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::execute_transaction::ExecuteTransactionInput {
            transact_statements: self.transact_statements,
            client_request_token: self.client_request_token,
            return_consumed_capacity: self.return_consumed_capacity,
        })
    }
}
