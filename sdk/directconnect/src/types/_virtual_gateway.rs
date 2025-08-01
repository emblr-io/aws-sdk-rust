// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a virtual private gateway for a private virtual interface.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualGateway {
    /// <p>The ID of the virtual private gateway.</p>
    pub virtual_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The state of the virtual private gateway. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p><code>pending</code>: Initial state after creating the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>available</code>: Ready for use by a private virtual interface.</p></li>
    /// <li>
    /// <p><code>deleting</code>: Initial state after deleting the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>deleted</code>: The virtual private gateway is deleted. The private virtual interface is unable to send traffic over this gateway.</p></li>
    /// </ul>
    pub virtual_gateway_state: ::std::option::Option<::std::string::String>,
}
impl VirtualGateway {
    /// <p>The ID of the virtual private gateway.</p>
    pub fn virtual_gateway_id(&self) -> ::std::option::Option<&str> {
        self.virtual_gateway_id.as_deref()
    }
    /// <p>The state of the virtual private gateway. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p><code>pending</code>: Initial state after creating the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>available</code>: Ready for use by a private virtual interface.</p></li>
    /// <li>
    /// <p><code>deleting</code>: Initial state after deleting the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>deleted</code>: The virtual private gateway is deleted. The private virtual interface is unable to send traffic over this gateway.</p></li>
    /// </ul>
    pub fn virtual_gateway_state(&self) -> ::std::option::Option<&str> {
        self.virtual_gateway_state.as_deref()
    }
}
impl VirtualGateway {
    /// Creates a new builder-style object to manufacture [`VirtualGateway`](crate::types::VirtualGateway).
    pub fn builder() -> crate::types::builders::VirtualGatewayBuilder {
        crate::types::builders::VirtualGatewayBuilder::default()
    }
}

/// A builder for [`VirtualGateway`](crate::types::VirtualGateway).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualGatewayBuilder {
    pub(crate) virtual_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_gateway_state: ::std::option::Option<::std::string::String>,
}
impl VirtualGatewayBuilder {
    /// <p>The ID of the virtual private gateway.</p>
    pub fn virtual_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual private gateway.</p>
    pub fn set_virtual_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_gateway_id = input;
        self
    }
    /// <p>The ID of the virtual private gateway.</p>
    pub fn get_virtual_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_gateway_id
    }
    /// <p>The state of the virtual private gateway. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p><code>pending</code>: Initial state after creating the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>available</code>: Ready for use by a private virtual interface.</p></li>
    /// <li>
    /// <p><code>deleting</code>: Initial state after deleting the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>deleted</code>: The virtual private gateway is deleted. The private virtual interface is unable to send traffic over this gateway.</p></li>
    /// </ul>
    pub fn virtual_gateway_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_gateway_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state of the virtual private gateway. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p><code>pending</code>: Initial state after creating the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>available</code>: Ready for use by a private virtual interface.</p></li>
    /// <li>
    /// <p><code>deleting</code>: Initial state after deleting the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>deleted</code>: The virtual private gateway is deleted. The private virtual interface is unable to send traffic over this gateway.</p></li>
    /// </ul>
    pub fn set_virtual_gateway_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_gateway_state = input;
        self
    }
    /// <p>The state of the virtual private gateway. The following are the possible values:</p>
    /// <ul>
    /// <li>
    /// <p><code>pending</code>: Initial state after creating the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>available</code>: Ready for use by a private virtual interface.</p></li>
    /// <li>
    /// <p><code>deleting</code>: Initial state after deleting the virtual private gateway.</p></li>
    /// <li>
    /// <p><code>deleted</code>: The virtual private gateway is deleted. The private virtual interface is unable to send traffic over this gateway.</p></li>
    /// </ul>
    pub fn get_virtual_gateway_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_gateway_state
    }
    /// Consumes the builder and constructs a [`VirtualGateway`](crate::types::VirtualGateway).
    pub fn build(self) -> crate::types::VirtualGateway {
        crate::types::VirtualGateway {
            virtual_gateway_id: self.virtual_gateway_id,
            virtual_gateway_state: self.virtual_gateway_state,
        }
    }
}
