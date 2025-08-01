// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConnectClientAddInsOutput {
    /// <p>Information about client add-ins.</p>
    pub add_ins: ::std::option::Option<::std::vec::Vec<crate::types::ConnectClientAddIn>>,
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConnectClientAddInsOutput {
    /// <p>Information about client add-ins.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.add_ins.is_none()`.
    pub fn add_ins(&self) -> &[crate::types::ConnectClientAddIn] {
        self.add_ins.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeConnectClientAddInsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeConnectClientAddInsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeConnectClientAddInsOutput`](crate::operation::describe_connect_client_add_ins::DescribeConnectClientAddInsOutput).
    pub fn builder() -> crate::operation::describe_connect_client_add_ins::builders::DescribeConnectClientAddInsOutputBuilder {
        crate::operation::describe_connect_client_add_ins::builders::DescribeConnectClientAddInsOutputBuilder::default()
    }
}

/// A builder for [`DescribeConnectClientAddInsOutput`](crate::operation::describe_connect_client_add_ins::DescribeConnectClientAddInsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConnectClientAddInsOutputBuilder {
    pub(crate) add_ins: ::std::option::Option<::std::vec::Vec<crate::types::ConnectClientAddIn>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeConnectClientAddInsOutputBuilder {
    /// Appends an item to `add_ins`.
    ///
    /// To override the contents of this collection use [`set_add_ins`](Self::set_add_ins).
    ///
    /// <p>Information about client add-ins.</p>
    pub fn add_ins(mut self, input: crate::types::ConnectClientAddIn) -> Self {
        let mut v = self.add_ins.unwrap_or_default();
        v.push(input);
        self.add_ins = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about client add-ins.</p>
    pub fn set_add_ins(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConnectClientAddIn>>) -> Self {
        self.add_ins = input;
        self
    }
    /// <p>Information about client add-ins.</p>
    pub fn get_add_ins(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConnectClientAddIn>> {
        &self.add_ins
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is null when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeConnectClientAddInsOutput`](crate::operation::describe_connect_client_add_ins::DescribeConnectClientAddInsOutput).
    pub fn build(self) -> crate::operation::describe_connect_client_add_ins::DescribeConnectClientAddInsOutput {
        crate::operation::describe_connect_client_add_ins::DescribeConnectClientAddInsOutput {
            add_ins: self.add_ins,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
