// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPeeringsOutput {
    /// <p>Lists the transit gateway peerings for the <code>ListPeerings</code> request.</p>
    pub peerings: ::std::option::Option<::std::vec::Vec<crate::types::Peering>>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPeeringsOutput {
    /// <p>Lists the transit gateway peerings for the <code>ListPeerings</code> request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.peerings.is_none()`.
    pub fn peerings(&self) -> &[crate::types::Peering] {
        self.peerings.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPeeringsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPeeringsOutput {
    /// Creates a new builder-style object to manufacture [`ListPeeringsOutput`](crate::operation::list_peerings::ListPeeringsOutput).
    pub fn builder() -> crate::operation::list_peerings::builders::ListPeeringsOutputBuilder {
        crate::operation::list_peerings::builders::ListPeeringsOutputBuilder::default()
    }
}

/// A builder for [`ListPeeringsOutput`](crate::operation::list_peerings::ListPeeringsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPeeringsOutputBuilder {
    pub(crate) peerings: ::std::option::Option<::std::vec::Vec<crate::types::Peering>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPeeringsOutputBuilder {
    /// Appends an item to `peerings`.
    ///
    /// To override the contents of this collection use [`set_peerings`](Self::set_peerings).
    ///
    /// <p>Lists the transit gateway peerings for the <code>ListPeerings</code> request.</p>
    pub fn peerings(mut self, input: crate::types::Peering) -> Self {
        let mut v = self.peerings.unwrap_or_default();
        v.push(input);
        self.peerings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists the transit gateway peerings for the <code>ListPeerings</code> request.</p>
    pub fn set_peerings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Peering>>) -> Self {
        self.peerings = input;
        self
    }
    /// <p>Lists the transit gateway peerings for the <code>ListPeerings</code> request.</p>
    pub fn get_peerings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Peering>> {
        &self.peerings
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPeeringsOutput`](crate::operation::list_peerings::ListPeeringsOutput).
    pub fn build(self) -> crate::operation::list_peerings::ListPeeringsOutput {
        crate::operation::list_peerings::ListPeeringsOutput {
            peerings: self.peerings,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
