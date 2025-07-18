// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTypedLinkFacetOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateTypedLinkFacetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateTypedLinkFacetOutput {
    /// Creates a new builder-style object to manufacture [`UpdateTypedLinkFacetOutput`](crate::operation::update_typed_link_facet::UpdateTypedLinkFacetOutput).
    pub fn builder() -> crate::operation::update_typed_link_facet::builders::UpdateTypedLinkFacetOutputBuilder {
        crate::operation::update_typed_link_facet::builders::UpdateTypedLinkFacetOutputBuilder::default()
    }
}

/// A builder for [`UpdateTypedLinkFacetOutput`](crate::operation::update_typed_link_facet::UpdateTypedLinkFacetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTypedLinkFacetOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateTypedLinkFacetOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateTypedLinkFacetOutput`](crate::operation::update_typed_link_facet::UpdateTypedLinkFacetOutput).
    pub fn build(self) -> crate::operation::update_typed_link_facet::UpdateTypedLinkFacetOutput {
        crate::operation::update_typed_link_facet::UpdateTypedLinkFacetOutput {
            _request_id: self._request_id,
        }
    }
}
