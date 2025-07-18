// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListConnectPeersInput {
    /// <p>The ID of a core network.</p>
    pub core_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the attachment.</p>
    pub connect_attachment_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListConnectPeersInput {
    /// <p>The ID of a core network.</p>
    pub fn core_network_id(&self) -> ::std::option::Option<&str> {
        self.core_network_id.as_deref()
    }
    /// <p>The ID of the attachment.</p>
    pub fn connect_attachment_id(&self) -> ::std::option::Option<&str> {
        self.connect_attachment_id.as_deref()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListConnectPeersInput {
    /// Creates a new builder-style object to manufacture [`ListConnectPeersInput`](crate::operation::list_connect_peers::ListConnectPeersInput).
    pub fn builder() -> crate::operation::list_connect_peers::builders::ListConnectPeersInputBuilder {
        crate::operation::list_connect_peers::builders::ListConnectPeersInputBuilder::default()
    }
}

/// A builder for [`ListConnectPeersInput`](crate::operation::list_connect_peers::ListConnectPeersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListConnectPeersInputBuilder {
    pub(crate) core_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) connect_attachment_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListConnectPeersInputBuilder {
    /// <p>The ID of a core network.</p>
    pub fn core_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.core_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of a core network.</p>
    pub fn set_core_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.core_network_id = input;
        self
    }
    /// <p>The ID of a core network.</p>
    pub fn get_core_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.core_network_id
    }
    /// <p>The ID of the attachment.</p>
    pub fn connect_attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connect_attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the attachment.</p>
    pub fn set_connect_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connect_attachment_id = input;
        self
    }
    /// <p>The ID of the attachment.</p>
    pub fn get_connect_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connect_attachment_id
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListConnectPeersInput`](crate::operation::list_connect_peers::ListConnectPeersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_connect_peers::ListConnectPeersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_connect_peers::ListConnectPeersInput {
            core_network_id: self.core_network_id,
            connect_attachment_id: self.connect_attachment_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
