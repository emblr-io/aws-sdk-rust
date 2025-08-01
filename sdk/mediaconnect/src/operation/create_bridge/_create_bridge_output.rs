// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBridgeOutput {
    /// <p>The name of the bridge that was created.</p>
    pub bridge: ::std::option::Option<crate::types::Bridge>,
    _request_id: Option<String>,
}
impl CreateBridgeOutput {
    /// <p>The name of the bridge that was created.</p>
    pub fn bridge(&self) -> ::std::option::Option<&crate::types::Bridge> {
        self.bridge.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBridgeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBridgeOutput {
    /// Creates a new builder-style object to manufacture [`CreateBridgeOutput`](crate::operation::create_bridge::CreateBridgeOutput).
    pub fn builder() -> crate::operation::create_bridge::builders::CreateBridgeOutputBuilder {
        crate::operation::create_bridge::builders::CreateBridgeOutputBuilder::default()
    }
}

/// A builder for [`CreateBridgeOutput`](crate::operation::create_bridge::CreateBridgeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBridgeOutputBuilder {
    pub(crate) bridge: ::std::option::Option<crate::types::Bridge>,
    _request_id: Option<String>,
}
impl CreateBridgeOutputBuilder {
    /// <p>The name of the bridge that was created.</p>
    pub fn bridge(mut self, input: crate::types::Bridge) -> Self {
        self.bridge = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the bridge that was created.</p>
    pub fn set_bridge(mut self, input: ::std::option::Option<crate::types::Bridge>) -> Self {
        self.bridge = input;
        self
    }
    /// <p>The name of the bridge that was created.</p>
    pub fn get_bridge(&self) -> &::std::option::Option<crate::types::Bridge> {
        &self.bridge
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBridgeOutput`](crate::operation::create_bridge::CreateBridgeOutput).
    pub fn build(self) -> crate::operation::create_bridge::CreateBridgeOutput {
        crate::operation::create_bridge::CreateBridgeOutput {
            bridge: self.bridge,
            _request_id: self._request_id,
        }
    }
}
