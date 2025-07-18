// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOperationsOutput {
    /// <p>Summary information about the operations that match the specified criteria.</p>
    pub operations: ::std::option::Option<::std::vec::Vec<crate::types::OperationSummary>>,
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListOperations</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> operations and then filters them based on the specified criteria. It's possible that no operations in the first <code>MaxResults</code> operations matched the specified criteria but that subsequent groups of <code>MaxResults</code> operations do contain operations that match the criteria.</p>
    /// </note>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListOperationsOutput {
    /// <p>Summary information about the operations that match the specified criteria.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.operations.is_none()`.
    pub fn operations(&self) -> &[crate::types::OperationSummary] {
        self.operations.as_deref().unwrap_or_default()
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListOperations</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> operations and then filters them based on the specified criteria. It's possible that no operations in the first <code>MaxResults</code> operations matched the specified criteria but that subsequent groups of <code>MaxResults</code> operations do contain operations that match the criteria.</p>
    /// </note>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListOperationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListOperationsOutput {
    /// Creates a new builder-style object to manufacture [`ListOperationsOutput`](crate::operation::list_operations::ListOperationsOutput).
    pub fn builder() -> crate::operation::list_operations::builders::ListOperationsOutputBuilder {
        crate::operation::list_operations::builders::ListOperationsOutputBuilder::default()
    }
}

/// A builder for [`ListOperationsOutput`](crate::operation::list_operations::ListOperationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOperationsOutputBuilder {
    pub(crate) operations: ::std::option::Option<::std::vec::Vec<crate::types::OperationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListOperationsOutputBuilder {
    /// Appends an item to `operations`.
    ///
    /// To override the contents of this collection use [`set_operations`](Self::set_operations).
    ///
    /// <p>Summary information about the operations that match the specified criteria.</p>
    pub fn operations(mut self, input: crate::types::OperationSummary) -> Self {
        let mut v = self.operations.unwrap_or_default();
        v.push(input);
        self.operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Summary information about the operations that match the specified criteria.</p>
    pub fn set_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OperationSummary>>) -> Self {
        self.operations = input;
        self
    }
    /// <p>Summary information about the operations that match the specified criteria.</p>
    pub fn get_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OperationSummary>> {
        &self.operations
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListOperations</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> operations and then filters them based on the specified criteria. It's possible that no operations in the first <code>MaxResults</code> operations matched the specified criteria but that subsequent groups of <code>MaxResults</code> operations do contain operations that match the criteria.</p>
    /// </note>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListOperations</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> operations and then filters them based on the specified criteria. It's possible that no operations in the first <code>MaxResults</code> operations matched the specified criteria but that subsequent groups of <code>MaxResults</code> operations do contain operations that match the criteria.</p>
    /// </note>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListOperations</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> operations and then filters them based on the specified criteria. It's possible that no operations in the first <code>MaxResults</code> operations matched the specified criteria but that subsequent groups of <code>MaxResults</code> operations do contain operations that match the criteria.</p>
    /// </note>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListOperationsOutput`](crate::operation::list_operations::ListOperationsOutput).
    pub fn build(self) -> crate::operation::list_operations::ListOperationsOutput {
        crate::operation::list_operations::ListOperationsOutput {
            operations: self.operations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
