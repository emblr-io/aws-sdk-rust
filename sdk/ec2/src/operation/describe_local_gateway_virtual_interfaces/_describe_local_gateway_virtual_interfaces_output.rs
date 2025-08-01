// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLocalGatewayVirtualInterfacesOutput {
    /// <p>Information about the virtual interfaces.</p>
    pub local_gateway_virtual_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::LocalGatewayVirtualInterface>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLocalGatewayVirtualInterfacesOutput {
    /// <p>Information about the virtual interfaces.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.local_gateway_virtual_interfaces.is_none()`.
    pub fn local_gateway_virtual_interfaces(&self) -> &[crate::types::LocalGatewayVirtualInterface] {
        self.local_gateway_virtual_interfaces.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLocalGatewayVirtualInterfacesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLocalGatewayVirtualInterfacesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLocalGatewayVirtualInterfacesOutput`](crate::operation::describe_local_gateway_virtual_interfaces::DescribeLocalGatewayVirtualInterfacesOutput).
    pub fn builder() -> crate::operation::describe_local_gateway_virtual_interfaces::builders::DescribeLocalGatewayVirtualInterfacesOutputBuilder {
        crate::operation::describe_local_gateway_virtual_interfaces::builders::DescribeLocalGatewayVirtualInterfacesOutputBuilder::default()
    }
}

/// A builder for [`DescribeLocalGatewayVirtualInterfacesOutput`](crate::operation::describe_local_gateway_virtual_interfaces::DescribeLocalGatewayVirtualInterfacesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLocalGatewayVirtualInterfacesOutputBuilder {
    pub(crate) local_gateway_virtual_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::LocalGatewayVirtualInterface>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLocalGatewayVirtualInterfacesOutputBuilder {
    /// Appends an item to `local_gateway_virtual_interfaces`.
    ///
    /// To override the contents of this collection use [`set_local_gateway_virtual_interfaces`](Self::set_local_gateway_virtual_interfaces).
    ///
    /// <p>Information about the virtual interfaces.</p>
    pub fn local_gateway_virtual_interfaces(mut self, input: crate::types::LocalGatewayVirtualInterface) -> Self {
        let mut v = self.local_gateway_virtual_interfaces.unwrap_or_default();
        v.push(input);
        self.local_gateway_virtual_interfaces = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the virtual interfaces.</p>
    pub fn set_local_gateway_virtual_interfaces(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::LocalGatewayVirtualInterface>>,
    ) -> Self {
        self.local_gateway_virtual_interfaces = input;
        self
    }
    /// <p>Information about the virtual interfaces.</p>
    pub fn get_local_gateway_virtual_interfaces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocalGatewayVirtualInterface>> {
        &self.local_gateway_virtual_interfaces
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
    /// Consumes the builder and constructs a [`DescribeLocalGatewayVirtualInterfacesOutput`](crate::operation::describe_local_gateway_virtual_interfaces::DescribeLocalGatewayVirtualInterfacesOutput).
    pub fn build(self) -> crate::operation::describe_local_gateway_virtual_interfaces::DescribeLocalGatewayVirtualInterfacesOutput {
        crate::operation::describe_local_gateway_virtual_interfaces::DescribeLocalGatewayVirtualInterfacesOutput {
            local_gateway_virtual_interfaces: self.local_gateway_virtual_interfaces,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
