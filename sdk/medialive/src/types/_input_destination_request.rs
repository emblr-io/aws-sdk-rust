// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Endpoint settings for a PUSH type input.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputDestinationRequest {
    /// A unique name for the location the RTMP stream is being pushed to.
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// If the push input has an input location of ON-PREM, ID the ID of the attached network.
    pub network: ::std::option::Option<::std::string::String>,
    /// If the push input has an input location of ON-PREM it's a requirement to specify what the route of the input is going to be on the customer local network.
    pub network_routes: ::std::option::Option<::std::vec::Vec<crate::types::InputRequestDestinationRoute>>,
    /// If the push input has an input location of ON-PREM it's optional to specify what the ip address of the input is going to be on the customer local network.
    pub static_ip_address: ::std::option::Option<::std::string::String>,
}
impl InputDestinationRequest {
    /// A unique name for the location the RTMP stream is being pushed to.
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// If the push input has an input location of ON-PREM, ID the ID of the attached network.
    pub fn network(&self) -> ::std::option::Option<&str> {
        self.network.as_deref()
    }
    /// If the push input has an input location of ON-PREM it's a requirement to specify what the route of the input is going to be on the customer local network.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_routes.is_none()`.
    pub fn network_routes(&self) -> &[crate::types::InputRequestDestinationRoute] {
        self.network_routes.as_deref().unwrap_or_default()
    }
    /// If the push input has an input location of ON-PREM it's optional to specify what the ip address of the input is going to be on the customer local network.
    pub fn static_ip_address(&self) -> ::std::option::Option<&str> {
        self.static_ip_address.as_deref()
    }
}
impl InputDestinationRequest {
    /// Creates a new builder-style object to manufacture [`InputDestinationRequest`](crate::types::InputDestinationRequest).
    pub fn builder() -> crate::types::builders::InputDestinationRequestBuilder {
        crate::types::builders::InputDestinationRequestBuilder::default()
    }
}

/// A builder for [`InputDestinationRequest`](crate::types::InputDestinationRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputDestinationRequestBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) network: ::std::option::Option<::std::string::String>,
    pub(crate) network_routes: ::std::option::Option<::std::vec::Vec<crate::types::InputRequestDestinationRoute>>,
    pub(crate) static_ip_address: ::std::option::Option<::std::string::String>,
}
impl InputDestinationRequestBuilder {
    /// A unique name for the location the RTMP stream is being pushed to.
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// A unique name for the location the RTMP stream is being pushed to.
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// A unique name for the location the RTMP stream is being pushed to.
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// If the push input has an input location of ON-PREM, ID the ID of the attached network.
    pub fn network(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network = ::std::option::Option::Some(input.into());
        self
    }
    /// If the push input has an input location of ON-PREM, ID the ID of the attached network.
    pub fn set_network(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network = input;
        self
    }
    /// If the push input has an input location of ON-PREM, ID the ID of the attached network.
    pub fn get_network(&self) -> &::std::option::Option<::std::string::String> {
        &self.network
    }
    /// Appends an item to `network_routes`.
    ///
    /// To override the contents of this collection use [`set_network_routes`](Self::set_network_routes).
    ///
    /// If the push input has an input location of ON-PREM it's a requirement to specify what the route of the input is going to be on the customer local network.
    pub fn network_routes(mut self, input: crate::types::InputRequestDestinationRoute) -> Self {
        let mut v = self.network_routes.unwrap_or_default();
        v.push(input);
        self.network_routes = ::std::option::Option::Some(v);
        self
    }
    /// If the push input has an input location of ON-PREM it's a requirement to specify what the route of the input is going to be on the customer local network.
    pub fn set_network_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InputRequestDestinationRoute>>) -> Self {
        self.network_routes = input;
        self
    }
    /// If the push input has an input location of ON-PREM it's a requirement to specify what the route of the input is going to be on the customer local network.
    pub fn get_network_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InputRequestDestinationRoute>> {
        &self.network_routes
    }
    /// If the push input has an input location of ON-PREM it's optional to specify what the ip address of the input is going to be on the customer local network.
    pub fn static_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.static_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// If the push input has an input location of ON-PREM it's optional to specify what the ip address of the input is going to be on the customer local network.
    pub fn set_static_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.static_ip_address = input;
        self
    }
    /// If the push input has an input location of ON-PREM it's optional to specify what the ip address of the input is going to be on the customer local network.
    pub fn get_static_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.static_ip_address
    }
    /// Consumes the builder and constructs a [`InputDestinationRequest`](crate::types::InputDestinationRequest).
    pub fn build(self) -> crate::types::InputDestinationRequest {
        crate::types::InputDestinationRequest {
            stream_name: self.stream_name,
            network: self.network,
            network_routes: self.network_routes,
            static_ip_address: self.static_ip_address,
        }
    }
}
