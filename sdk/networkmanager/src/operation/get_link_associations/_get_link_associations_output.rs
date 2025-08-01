// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLinkAssociationsOutput {
    /// <p>The link associations.</p>
    pub link_associations: ::std::option::Option<::std::vec::Vec<crate::types::LinkAssociation>>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetLinkAssociationsOutput {
    /// <p>The link associations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.link_associations.is_none()`.
    pub fn link_associations(&self) -> &[crate::types::LinkAssociation] {
        self.link_associations.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetLinkAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLinkAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`GetLinkAssociationsOutput`](crate::operation::get_link_associations::GetLinkAssociationsOutput).
    pub fn builder() -> crate::operation::get_link_associations::builders::GetLinkAssociationsOutputBuilder {
        crate::operation::get_link_associations::builders::GetLinkAssociationsOutputBuilder::default()
    }
}

/// A builder for [`GetLinkAssociationsOutput`](crate::operation::get_link_associations::GetLinkAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLinkAssociationsOutputBuilder {
    pub(crate) link_associations: ::std::option::Option<::std::vec::Vec<crate::types::LinkAssociation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetLinkAssociationsOutputBuilder {
    /// Appends an item to `link_associations`.
    ///
    /// To override the contents of this collection use [`set_link_associations`](Self::set_link_associations).
    ///
    /// <p>The link associations.</p>
    pub fn link_associations(mut self, input: crate::types::LinkAssociation) -> Self {
        let mut v = self.link_associations.unwrap_or_default();
        v.push(input);
        self.link_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The link associations.</p>
    pub fn set_link_associations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LinkAssociation>>) -> Self {
        self.link_associations = input;
        self
    }
    /// <p>The link associations.</p>
    pub fn get_link_associations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LinkAssociation>> {
        &self.link_associations
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
    /// Consumes the builder and constructs a [`GetLinkAssociationsOutput`](crate::operation::get_link_associations::GetLinkAssociationsOutput).
    pub fn build(self) -> crate::operation::get_link_associations::GetLinkAssociationsOutput {
        crate::operation::get_link_associations::GetLinkAssociationsOutput {
            link_associations: self.link_associations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
