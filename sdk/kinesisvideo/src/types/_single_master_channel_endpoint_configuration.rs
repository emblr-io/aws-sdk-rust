// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains the endpoint configuration for the <code>SINGLE_MASTER</code> channel type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SingleMasterChannelEndpointConfiguration {
    /// <p>This property is used to determine the nature of communication over this <code>SINGLE_MASTER</code> signaling channel. If <code>WSS</code> is specified, this API returns a websocket endpoint. If <code>HTTPS</code> is specified, this API returns an <code>HTTPS</code> endpoint.</p>
    pub protocols: ::std::option::Option<::std::vec::Vec<crate::types::ChannelProtocol>>,
    /// <p>This property is used to determine messaging permissions in this <code>SINGLE_MASTER</code> signaling channel. If <code>MASTER</code> is specified, this API returns an endpoint that a client can use to receive offers from and send answers to any of the viewers on this signaling channel. If <code>VIEWER</code> is specified, this API returns an endpoint that a client can use only to send offers to another <code>MASTER</code> client on this signaling channel.</p>
    pub role: ::std::option::Option<crate::types::ChannelRole>,
}
impl SingleMasterChannelEndpointConfiguration {
    /// <p>This property is used to determine the nature of communication over this <code>SINGLE_MASTER</code> signaling channel. If <code>WSS</code> is specified, this API returns a websocket endpoint. If <code>HTTPS</code> is specified, this API returns an <code>HTTPS</code> endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.protocols.is_none()`.
    pub fn protocols(&self) -> &[crate::types::ChannelProtocol] {
        self.protocols.as_deref().unwrap_or_default()
    }
    /// <p>This property is used to determine messaging permissions in this <code>SINGLE_MASTER</code> signaling channel. If <code>MASTER</code> is specified, this API returns an endpoint that a client can use to receive offers from and send answers to any of the viewers on this signaling channel. If <code>VIEWER</code> is specified, this API returns an endpoint that a client can use only to send offers to another <code>MASTER</code> client on this signaling channel.</p>
    pub fn role(&self) -> ::std::option::Option<&crate::types::ChannelRole> {
        self.role.as_ref()
    }
}
impl SingleMasterChannelEndpointConfiguration {
    /// Creates a new builder-style object to manufacture [`SingleMasterChannelEndpointConfiguration`](crate::types::SingleMasterChannelEndpointConfiguration).
    pub fn builder() -> crate::types::builders::SingleMasterChannelEndpointConfigurationBuilder {
        crate::types::builders::SingleMasterChannelEndpointConfigurationBuilder::default()
    }
}

/// A builder for [`SingleMasterChannelEndpointConfiguration`](crate::types::SingleMasterChannelEndpointConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SingleMasterChannelEndpointConfigurationBuilder {
    pub(crate) protocols: ::std::option::Option<::std::vec::Vec<crate::types::ChannelProtocol>>,
    pub(crate) role: ::std::option::Option<crate::types::ChannelRole>,
}
impl SingleMasterChannelEndpointConfigurationBuilder {
    /// Appends an item to `protocols`.
    ///
    /// To override the contents of this collection use [`set_protocols`](Self::set_protocols).
    ///
    /// <p>This property is used to determine the nature of communication over this <code>SINGLE_MASTER</code> signaling channel. If <code>WSS</code> is specified, this API returns a websocket endpoint. If <code>HTTPS</code> is specified, this API returns an <code>HTTPS</code> endpoint.</p>
    pub fn protocols(mut self, input: crate::types::ChannelProtocol) -> Self {
        let mut v = self.protocols.unwrap_or_default();
        v.push(input);
        self.protocols = ::std::option::Option::Some(v);
        self
    }
    /// <p>This property is used to determine the nature of communication over this <code>SINGLE_MASTER</code> signaling channel. If <code>WSS</code> is specified, this API returns a websocket endpoint. If <code>HTTPS</code> is specified, this API returns an <code>HTTPS</code> endpoint.</p>
    pub fn set_protocols(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ChannelProtocol>>) -> Self {
        self.protocols = input;
        self
    }
    /// <p>This property is used to determine the nature of communication over this <code>SINGLE_MASTER</code> signaling channel. If <code>WSS</code> is specified, this API returns a websocket endpoint. If <code>HTTPS</code> is specified, this API returns an <code>HTTPS</code> endpoint.</p>
    pub fn get_protocols(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChannelProtocol>> {
        &self.protocols
    }
    /// <p>This property is used to determine messaging permissions in this <code>SINGLE_MASTER</code> signaling channel. If <code>MASTER</code> is specified, this API returns an endpoint that a client can use to receive offers from and send answers to any of the viewers on this signaling channel. If <code>VIEWER</code> is specified, this API returns an endpoint that a client can use only to send offers to another <code>MASTER</code> client on this signaling channel.</p>
    pub fn role(mut self, input: crate::types::ChannelRole) -> Self {
        self.role = ::std::option::Option::Some(input);
        self
    }
    /// <p>This property is used to determine messaging permissions in this <code>SINGLE_MASTER</code> signaling channel. If <code>MASTER</code> is specified, this API returns an endpoint that a client can use to receive offers from and send answers to any of the viewers on this signaling channel. If <code>VIEWER</code> is specified, this API returns an endpoint that a client can use only to send offers to another <code>MASTER</code> client on this signaling channel.</p>
    pub fn set_role(mut self, input: ::std::option::Option<crate::types::ChannelRole>) -> Self {
        self.role = input;
        self
    }
    /// <p>This property is used to determine messaging permissions in this <code>SINGLE_MASTER</code> signaling channel. If <code>MASTER</code> is specified, this API returns an endpoint that a client can use to receive offers from and send answers to any of the viewers on this signaling channel. If <code>VIEWER</code> is specified, this API returns an endpoint that a client can use only to send offers to another <code>MASTER</code> client on this signaling channel.</p>
    pub fn get_role(&self) -> &::std::option::Option<crate::types::ChannelRole> {
        &self.role
    }
    /// Consumes the builder and constructs a [`SingleMasterChannelEndpointConfiguration`](crate::types::SingleMasterChannelEndpointConfiguration).
    pub fn build(self) -> crate::types::SingleMasterChannelEndpointConfiguration {
        crate::types::SingleMasterChannelEndpointConfiguration {
            protocols: self.protocols,
            role: self.role,
        }
    }
}
