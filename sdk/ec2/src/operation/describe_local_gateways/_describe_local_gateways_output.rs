// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLocalGatewaysOutput {
    /// <p>Information about the local gateways.</p>
    pub local_gateways: ::std::option::Option<::std::vec::Vec<crate::types::LocalGateway>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLocalGatewaysOutput {
    /// <p>Information about the local gateways.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.local_gateways.is_none()`.
    pub fn local_gateways(&self) -> &[crate::types::LocalGateway] {
        self.local_gateways.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLocalGatewaysOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLocalGatewaysOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLocalGatewaysOutput`](crate::operation::describe_local_gateways::DescribeLocalGatewaysOutput).
    pub fn builder() -> crate::operation::describe_local_gateways::builders::DescribeLocalGatewaysOutputBuilder {
        crate::operation::describe_local_gateways::builders::DescribeLocalGatewaysOutputBuilder::default()
    }
}

/// A builder for [`DescribeLocalGatewaysOutput`](crate::operation::describe_local_gateways::DescribeLocalGatewaysOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLocalGatewaysOutputBuilder {
    pub(crate) local_gateways: ::std::option::Option<::std::vec::Vec<crate::types::LocalGateway>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLocalGatewaysOutputBuilder {
    /// Appends an item to `local_gateways`.
    ///
    /// To override the contents of this collection use [`set_local_gateways`](Self::set_local_gateways).
    ///
    /// <p>Information about the local gateways.</p>
    pub fn local_gateways(mut self, input: crate::types::LocalGateway) -> Self {
        let mut v = self.local_gateways.unwrap_or_default();
        v.push(input);
        self.local_gateways = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the local gateways.</p>
    pub fn set_local_gateways(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LocalGateway>>) -> Self {
        self.local_gateways = input;
        self
    }
    /// <p>Information about the local gateways.</p>
    pub fn get_local_gateways(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocalGateway>> {
        &self.local_gateways
    }
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeLocalGatewaysOutput`](crate::operation::describe_local_gateways::DescribeLocalGatewaysOutput).
    pub fn build(self) -> crate::operation::describe_local_gateways::DescribeLocalGatewaysOutput {
        crate::operation::describe_local_gateways::DescribeLocalGatewaysOutput {
            local_gateways: self.local_gateways,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
