// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A PartiQL batch statement request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchStatementRequest {
    /// <p>A valid PartiQL statement.</p>
    pub statement: ::std::string::String,
    /// <p>The parameters associated with a PartiQL statement in the batch request.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::AttributeValue>>,
    /// <p>The read consistency of the PartiQL batch request.</p>
    pub consistent_read: ::std::option::Option<bool>,
    /// <p>An optional parameter that returns the item attributes for a PartiQL batch request operation that failed a condition check.</p>
    /// <p>There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed.</p>
    pub return_values_on_condition_check_failure: ::std::option::Option<crate::types::ReturnValuesOnConditionCheckFailure>,
}
impl BatchStatementRequest {
    /// <p>A valid PartiQL statement.</p>
    pub fn statement(&self) -> &str {
        use std::ops::Deref;
        self.statement.deref()
    }
    /// <p>The parameters associated with a PartiQL statement in the batch request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::AttributeValue] {
        self.parameters.as_deref().unwrap_or_default()
    }
    /// <p>The read consistency of the PartiQL batch request.</p>
    pub fn consistent_read(&self) -> ::std::option::Option<bool> {
        self.consistent_read
    }
    /// <p>An optional parameter that returns the item attributes for a PartiQL batch request operation that failed a condition check.</p>
    /// <p>There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed.</p>
    pub fn return_values_on_condition_check_failure(&self) -> ::std::option::Option<&crate::types::ReturnValuesOnConditionCheckFailure> {
        self.return_values_on_condition_check_failure.as_ref()
    }
}
impl BatchStatementRequest {
    /// Creates a new builder-style object to manufacture [`BatchStatementRequest`](crate::types::BatchStatementRequest).
    pub fn builder() -> crate::types::builders::BatchStatementRequestBuilder {
        crate::types::builders::BatchStatementRequestBuilder::default()
    }
}

/// A builder for [`BatchStatementRequest`](crate::types::BatchStatementRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchStatementRequestBuilder {
    pub(crate) statement: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::AttributeValue>>,
    pub(crate) consistent_read: ::std::option::Option<bool>,
    pub(crate) return_values_on_condition_check_failure: ::std::option::Option<crate::types::ReturnValuesOnConditionCheckFailure>,
}
impl BatchStatementRequestBuilder {
    /// <p>A valid PartiQL statement.</p>
    /// This field is required.
    pub fn statement(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid PartiQL statement.</p>
    pub fn set_statement(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement = input;
        self
    }
    /// <p>A valid PartiQL statement.</p>
    pub fn get_statement(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement
    }
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters associated with a PartiQL statement in the batch request.</p>
    pub fn parameters(mut self, input: crate::types::AttributeValue) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The parameters associated with a PartiQL statement in the batch request.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttributeValue>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters associated with a PartiQL statement in the batch request.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttributeValue>> {
        &self.parameters
    }
    /// <p>The read consistency of the PartiQL batch request.</p>
    pub fn consistent_read(mut self, input: bool) -> Self {
        self.consistent_read = ::std::option::Option::Some(input);
        self
    }
    /// <p>The read consistency of the PartiQL batch request.</p>
    pub fn set_consistent_read(mut self, input: ::std::option::Option<bool>) -> Self {
        self.consistent_read = input;
        self
    }
    /// <p>The read consistency of the PartiQL batch request.</p>
    pub fn get_consistent_read(&self) -> &::std::option::Option<bool> {
        &self.consistent_read
    }
    /// <p>An optional parameter that returns the item attributes for a PartiQL batch request operation that failed a condition check.</p>
    /// <p>There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed.</p>
    pub fn return_values_on_condition_check_failure(mut self, input: crate::types::ReturnValuesOnConditionCheckFailure) -> Self {
        self.return_values_on_condition_check_failure = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional parameter that returns the item attributes for a PartiQL batch request operation that failed a condition check.</p>
    /// <p>There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed.</p>
    pub fn set_return_values_on_condition_check_failure(
        mut self,
        input: ::std::option::Option<crate::types::ReturnValuesOnConditionCheckFailure>,
    ) -> Self {
        self.return_values_on_condition_check_failure = input;
        self
    }
    /// <p>An optional parameter that returns the item attributes for a PartiQL batch request operation that failed a condition check.</p>
    /// <p>There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed.</p>
    pub fn get_return_values_on_condition_check_failure(&self) -> &::std::option::Option<crate::types::ReturnValuesOnConditionCheckFailure> {
        &self.return_values_on_condition_check_failure
    }
    /// Consumes the builder and constructs a [`BatchStatementRequest`](crate::types::BatchStatementRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`statement`](crate::types::builders::BatchStatementRequestBuilder::statement)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchStatementRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchStatementRequest {
            statement: self.statement.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "statement",
                    "statement was not specified but it is required when building BatchStatementRequest",
                )
            })?,
            parameters: self.parameters,
            consistent_read: self.consistent_read,
            return_values_on_condition_check_failure: self.return_values_on_condition_check_failure,
        })
    }
}
