// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListWorkloadsOutput {
    /// <p>Information about the workloads.</p>
    pub workloads: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadDataSummary>>,
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListWorkloadsOutput {
    /// <p>Information about the workloads.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.workloads.is_none()`.
    pub fn workloads(&self) -> &[crate::types::WorkloadDataSummary] {
        self.workloads.as_deref().unwrap_or_default()
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListWorkloadsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListWorkloadsOutput {
    /// Creates a new builder-style object to manufacture [`ListWorkloadsOutput`](crate::operation::list_workloads::ListWorkloadsOutput).
    pub fn builder() -> crate::operation::list_workloads::builders::ListWorkloadsOutputBuilder {
        crate::operation::list_workloads::builders::ListWorkloadsOutputBuilder::default()
    }
}

/// A builder for [`ListWorkloadsOutput`](crate::operation::list_workloads::ListWorkloadsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListWorkloadsOutputBuilder {
    pub(crate) workloads: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadDataSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListWorkloadsOutputBuilder {
    /// Appends an item to `workloads`.
    ///
    /// To override the contents of this collection use [`set_workloads`](Self::set_workloads).
    ///
    /// <p>Information about the workloads.</p>
    pub fn workloads(mut self, input: crate::types::WorkloadDataSummary) -> Self {
        let mut v = self.workloads.unwrap_or_default();
        v.push(input);
        self.workloads = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the workloads.</p>
    pub fn set_workloads(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadDataSummary>>) -> Self {
        self.workloads = input;
        self
    }
    /// <p>Information about the workloads.</p>
    pub fn get_workloads(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkloadDataSummary>> {
        &self.workloads
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
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
    /// Consumes the builder and constructs a [`ListWorkloadsOutput`](crate::operation::list_workloads::ListWorkloadsOutput).
    pub fn build(self) -> crate::operation::list_workloads::ListWorkloadsOutput {
        crate::operation::list_workloads::ListWorkloadsOutput {
            workloads: self.workloads,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
