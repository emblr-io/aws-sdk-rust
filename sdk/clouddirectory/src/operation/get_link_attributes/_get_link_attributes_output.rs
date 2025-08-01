// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLinkAttributesOutput {
    /// <p>The attributes that are associated with the typed link.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::AttributeKeyAndValue>>,
    _request_id: Option<String>,
}
impl GetLinkAttributesOutput {
    /// <p>The attributes that are associated with the typed link.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::AttributeKeyAndValue] {
        self.attributes.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetLinkAttributesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLinkAttributesOutput {
    /// Creates a new builder-style object to manufacture [`GetLinkAttributesOutput`](crate::operation::get_link_attributes::GetLinkAttributesOutput).
    pub fn builder() -> crate::operation::get_link_attributes::builders::GetLinkAttributesOutputBuilder {
        crate::operation::get_link_attributes::builders::GetLinkAttributesOutputBuilder::default()
    }
}

/// A builder for [`GetLinkAttributesOutput`](crate::operation::get_link_attributes::GetLinkAttributesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLinkAttributesOutputBuilder {
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::AttributeKeyAndValue>>,
    _request_id: Option<String>,
}
impl GetLinkAttributesOutputBuilder {
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>The attributes that are associated with the typed link.</p>
    pub fn attributes(mut self, input: crate::types::AttributeKeyAndValue) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The attributes that are associated with the typed link.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttributeKeyAndValue>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>The attributes that are associated with the typed link.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttributeKeyAndValue>> {
        &self.attributes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLinkAttributesOutput`](crate::operation::get_link_attributes::GetLinkAttributesOutput).
    pub fn build(self) -> crate::operation::get_link_attributes::GetLinkAttributesOutput {
        crate::operation::get_link_attributes::GetLinkAttributesOutput {
            attributes: self.attributes,
            _request_id: self._request_id,
        }
    }
}
