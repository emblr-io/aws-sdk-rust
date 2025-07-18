// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSolNetworkOperationsOutput {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Lists network operation occurrences. Lifecycle management operations are deploy, update, or delete operations.</p>
    pub network_operations: ::std::option::Option<::std::vec::Vec<crate::types::ListSolNetworkOperationsInfo>>,
    _request_id: Option<String>,
}
impl ListSolNetworkOperationsOutput {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Lists network operation occurrences. Lifecycle management operations are deploy, update, or delete operations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_operations.is_none()`.
    pub fn network_operations(&self) -> &[crate::types::ListSolNetworkOperationsInfo] {
        self.network_operations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSolNetworkOperationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSolNetworkOperationsOutput {
    /// Creates a new builder-style object to manufacture [`ListSolNetworkOperationsOutput`](crate::operation::list_sol_network_operations::ListSolNetworkOperationsOutput).
    pub fn builder() -> crate::operation::list_sol_network_operations::builders::ListSolNetworkOperationsOutputBuilder {
        crate::operation::list_sol_network_operations::builders::ListSolNetworkOperationsOutputBuilder::default()
    }
}

/// A builder for [`ListSolNetworkOperationsOutput`](crate::operation::list_sol_network_operations::ListSolNetworkOperationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSolNetworkOperationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) network_operations: ::std::option::Option<::std::vec::Vec<crate::types::ListSolNetworkOperationsInfo>>,
    _request_id: Option<String>,
}
impl ListSolNetworkOperationsOutputBuilder {
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `network_operations`.
    ///
    /// To override the contents of this collection use [`set_network_operations`](Self::set_network_operations).
    ///
    /// <p>Lists network operation occurrences. Lifecycle management operations are deploy, update, or delete operations.</p>
    pub fn network_operations(mut self, input: crate::types::ListSolNetworkOperationsInfo) -> Self {
        let mut v = self.network_operations.unwrap_or_default();
        v.push(input);
        self.network_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists network operation occurrences. Lifecycle management operations are deploy, update, or delete operations.</p>
    pub fn set_network_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ListSolNetworkOperationsInfo>>) -> Self {
        self.network_operations = input;
        self
    }
    /// <p>Lists network operation occurrences. Lifecycle management operations are deploy, update, or delete operations.</p>
    pub fn get_network_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ListSolNetworkOperationsInfo>> {
        &self.network_operations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSolNetworkOperationsOutput`](crate::operation::list_sol_network_operations::ListSolNetworkOperationsOutput).
    pub fn build(self) -> crate::operation::list_sol_network_operations::ListSolNetworkOperationsOutput {
        crate::operation::list_sol_network_operations::ListSolNetworkOperationsOutput {
            next_token: self.next_token,
            network_operations: self.network_operations,
            _request_id: self._request_id,
        }
    }
}
