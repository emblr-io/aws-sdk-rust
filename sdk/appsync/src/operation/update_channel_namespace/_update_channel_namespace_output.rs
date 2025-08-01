// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateChannelNamespaceOutput {
    /// <p>The <code>ChannelNamespace</code> object.</p>
    pub channel_namespace: ::std::option::Option<crate::types::ChannelNamespace>,
    _request_id: Option<String>,
}
impl UpdateChannelNamespaceOutput {
    /// <p>The <code>ChannelNamespace</code> object.</p>
    pub fn channel_namespace(&self) -> ::std::option::Option<&crate::types::ChannelNamespace> {
        self.channel_namespace.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateChannelNamespaceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateChannelNamespaceOutput {
    /// Creates a new builder-style object to manufacture [`UpdateChannelNamespaceOutput`](crate::operation::update_channel_namespace::UpdateChannelNamespaceOutput).
    pub fn builder() -> crate::operation::update_channel_namespace::builders::UpdateChannelNamespaceOutputBuilder {
        crate::operation::update_channel_namespace::builders::UpdateChannelNamespaceOutputBuilder::default()
    }
}

/// A builder for [`UpdateChannelNamespaceOutput`](crate::operation::update_channel_namespace::UpdateChannelNamespaceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateChannelNamespaceOutputBuilder {
    pub(crate) channel_namespace: ::std::option::Option<crate::types::ChannelNamespace>,
    _request_id: Option<String>,
}
impl UpdateChannelNamespaceOutputBuilder {
    /// <p>The <code>ChannelNamespace</code> object.</p>
    pub fn channel_namespace(mut self, input: crate::types::ChannelNamespace) -> Self {
        self.channel_namespace = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>ChannelNamespace</code> object.</p>
    pub fn set_channel_namespace(mut self, input: ::std::option::Option<crate::types::ChannelNamespace>) -> Self {
        self.channel_namespace = input;
        self
    }
    /// <p>The <code>ChannelNamespace</code> object.</p>
    pub fn get_channel_namespace(&self) -> &::std::option::Option<crate::types::ChannelNamespace> {
        &self.channel_namespace
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateChannelNamespaceOutput`](crate::operation::update_channel_namespace::UpdateChannelNamespaceOutput).
    pub fn build(self) -> crate::operation::update_channel_namespace::UpdateChannelNamespaceOutput {
        crate::operation::update_channel_namespace::UpdateChannelNamespaceOutput {
            channel_namespace: self.channel_namespace,
            _request_id: self._request_id,
        }
    }
}
