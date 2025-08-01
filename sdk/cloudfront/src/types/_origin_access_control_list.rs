// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of CloudFront origin access controls.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OriginAccessControlList {
    /// <p>The value of the <code>Marker</code> field that was provided in the request.</p>
    pub marker: ::std::string::String,
    /// <p>If there are more items in the list than are in this response, this element is present. It contains the value to use in the <code>Marker</code> field of another request to continue listing origin access controls.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of origin access controls requested.</p>
    pub max_items: i32,
    /// <p>If there are more items in the list than are in this response, this value is <code>true</code>.</p>
    pub is_truncated: bool,
    /// <p>The number of origin access controls returned in the response.</p>
    pub quantity: i32,
    /// <p>Contains the origin access controls in the list.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::OriginAccessControlSummary>>,
}
impl OriginAccessControlList {
    /// <p>The value of the <code>Marker</code> field that was provided in the request.</p>
    pub fn marker(&self) -> &str {
        use std::ops::Deref;
        self.marker.deref()
    }
    /// <p>If there are more items in the list than are in this response, this element is present. It contains the value to use in the <code>Marker</code> field of another request to continue listing origin access controls.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>The maximum number of origin access controls requested.</p>
    pub fn max_items(&self) -> i32 {
        self.max_items
    }
    /// <p>If there are more items in the list than are in this response, this value is <code>true</code>.</p>
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }
    /// <p>The number of origin access controls returned in the response.</p>
    pub fn quantity(&self) -> i32 {
        self.quantity
    }
    /// <p>Contains the origin access controls in the list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::OriginAccessControlSummary] {
        self.items.as_deref().unwrap_or_default()
    }
}
impl OriginAccessControlList {
    /// Creates a new builder-style object to manufacture [`OriginAccessControlList`](crate::types::OriginAccessControlList).
    pub fn builder() -> crate::types::builders::OriginAccessControlListBuilder {
        crate::types::builders::OriginAccessControlListBuilder::default()
    }
}

/// A builder for [`OriginAccessControlList`](crate::types::OriginAccessControlList).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OriginAccessControlListBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) quantity: ::std::option::Option<i32>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::OriginAccessControlSummary>>,
}
impl OriginAccessControlListBuilder {
    /// <p>The value of the <code>Marker</code> field that was provided in the request.</p>
    /// This field is required.
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the <code>Marker</code> field that was provided in the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The value of the <code>Marker</code> field that was provided in the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>If there are more items in the list than are in this response, this element is present. It contains the value to use in the <code>Marker</code> field of another request to continue listing origin access controls.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more items in the list than are in this response, this element is present. It contains the value to use in the <code>Marker</code> field of another request to continue listing origin access controls.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>If there are more items in the list than are in this response, this element is present. It contains the value to use in the <code>Marker</code> field of another request to continue listing origin access controls.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// <p>The maximum number of origin access controls requested.</p>
    /// This field is required.
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of origin access controls requested.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of origin access controls requested.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// <p>If there are more items in the list than are in this response, this value is <code>true</code>.</p>
    /// This field is required.
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>If there are more items in the list than are in this response, this value is <code>true</code>.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>If there are more items in the list than are in this response, this value is <code>true</code>.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>The number of origin access controls returned in the response.</p>
    /// This field is required.
    pub fn quantity(mut self, input: i32) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of origin access controls returned in the response.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The number of origin access controls returned in the response.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i32> {
        &self.quantity
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>Contains the origin access controls in the list.</p>
    pub fn items(mut self, input: crate::types::OriginAccessControlSummary) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the origin access controls in the list.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OriginAccessControlSummary>>) -> Self {
        self.items = input;
        self
    }
    /// <p>Contains the origin access controls in the list.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OriginAccessControlSummary>> {
        &self.items
    }
    /// Consumes the builder and constructs a [`OriginAccessControlList`](crate::types::OriginAccessControlList).
    /// This method will fail if any of the following fields are not set:
    /// - [`marker`](crate::types::builders::OriginAccessControlListBuilder::marker)
    /// - [`max_items`](crate::types::builders::OriginAccessControlListBuilder::max_items)
    /// - [`is_truncated`](crate::types::builders::OriginAccessControlListBuilder::is_truncated)
    /// - [`quantity`](crate::types::builders::OriginAccessControlListBuilder::quantity)
    pub fn build(self) -> ::std::result::Result<crate::types::OriginAccessControlList, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OriginAccessControlList {
            marker: self.marker.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "marker",
                    "marker was not specified but it is required when building OriginAccessControlList",
                )
            })?,
            next_marker: self.next_marker,
            max_items: self.max_items.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_items",
                    "max_items was not specified but it is required when building OriginAccessControlList",
                )
            })?,
            is_truncated: self.is_truncated.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "is_truncated",
                    "is_truncated was not specified but it is required when building OriginAccessControlList",
                )
            })?,
            quantity: self.quantity.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quantity",
                    "quantity was not specified but it is required when building OriginAccessControlList",
                )
            })?,
            items: self.items,
        })
    }
}
