// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGlobalNetworkOutput {
    /// <p>Information about the global network object.</p>
    pub global_network: ::std::option::Option<crate::types::GlobalNetwork>,
    _request_id: Option<String>,
}
impl CreateGlobalNetworkOutput {
    /// <p>Information about the global network object.</p>
    pub fn global_network(&self) -> ::std::option::Option<&crate::types::GlobalNetwork> {
        self.global_network.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateGlobalNetworkOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateGlobalNetworkOutput {
    /// Creates a new builder-style object to manufacture [`CreateGlobalNetworkOutput`](crate::operation::create_global_network::CreateGlobalNetworkOutput).
    pub fn builder() -> crate::operation::create_global_network::builders::CreateGlobalNetworkOutputBuilder {
        crate::operation::create_global_network::builders::CreateGlobalNetworkOutputBuilder::default()
    }
}

/// A builder for [`CreateGlobalNetworkOutput`](crate::operation::create_global_network::CreateGlobalNetworkOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGlobalNetworkOutputBuilder {
    pub(crate) global_network: ::std::option::Option<crate::types::GlobalNetwork>,
    _request_id: Option<String>,
}
impl CreateGlobalNetworkOutputBuilder {
    /// <p>Information about the global network object.</p>
    pub fn global_network(mut self, input: crate::types::GlobalNetwork) -> Self {
        self.global_network = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the global network object.</p>
    pub fn set_global_network(mut self, input: ::std::option::Option<crate::types::GlobalNetwork>) -> Self {
        self.global_network = input;
        self
    }
    /// <p>Information about the global network object.</p>
    pub fn get_global_network(&self) -> &::std::option::Option<crate::types::GlobalNetwork> {
        &self.global_network
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateGlobalNetworkOutput`](crate::operation::create_global_network::CreateGlobalNetworkOutput).
    pub fn build(self) -> crate::operation::create_global_network::CreateGlobalNetworkOutput {
        crate::operation::create_global_network::CreateGlobalNetworkOutput {
            global_network: self.global_network,
            _request_id: self._request_id,
        }
    }
}
