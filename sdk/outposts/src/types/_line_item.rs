// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a line item.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LineItem {
    /// <p>The ID of the catalog item.</p>
    pub catalog_item_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the line item.</p>
    pub line_item_id: ::std::option::Option<::std::string::String>,
    /// <p>The quantity of the line item.</p>
    pub quantity: ::std::option::Option<i32>,
    /// <p>The status of the line item.</p>
    pub status: ::std::option::Option<crate::types::LineItemStatus>,
    /// <p>Information about a line item shipment.</p>
    pub shipment_information: ::std::option::Option<crate::types::ShipmentInformation>,
    /// <p>Information about assets.</p>
    pub asset_information_list: ::std::option::Option<::std::vec::Vec<crate::types::LineItemAssetInformation>>,
    /// <p>The ID of the previous line item.</p>
    pub previous_line_item_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the previous order.</p>
    pub previous_order_id: ::std::option::Option<::std::string::String>,
}
impl LineItem {
    /// <p>The ID of the catalog item.</p>
    pub fn catalog_item_id(&self) -> ::std::option::Option<&str> {
        self.catalog_item_id.as_deref()
    }
    /// <p>The ID of the line item.</p>
    pub fn line_item_id(&self) -> ::std::option::Option<&str> {
        self.line_item_id.as_deref()
    }
    /// <p>The quantity of the line item.</p>
    pub fn quantity(&self) -> ::std::option::Option<i32> {
        self.quantity
    }
    /// <p>The status of the line item.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::LineItemStatus> {
        self.status.as_ref()
    }
    /// <p>Information about a line item shipment.</p>
    pub fn shipment_information(&self) -> ::std::option::Option<&crate::types::ShipmentInformation> {
        self.shipment_information.as_ref()
    }
    /// <p>Information about assets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.asset_information_list.is_none()`.
    pub fn asset_information_list(&self) -> &[crate::types::LineItemAssetInformation] {
        self.asset_information_list.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the previous line item.</p>
    pub fn previous_line_item_id(&self) -> ::std::option::Option<&str> {
        self.previous_line_item_id.as_deref()
    }
    /// <p>The ID of the previous order.</p>
    pub fn previous_order_id(&self) -> ::std::option::Option<&str> {
        self.previous_order_id.as_deref()
    }
}
impl LineItem {
    /// Creates a new builder-style object to manufacture [`LineItem`](crate::types::LineItem).
    pub fn builder() -> crate::types::builders::LineItemBuilder {
        crate::types::builders::LineItemBuilder::default()
    }
}

/// A builder for [`LineItem`](crate::types::LineItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LineItemBuilder {
    pub(crate) catalog_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) line_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) quantity: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::LineItemStatus>,
    pub(crate) shipment_information: ::std::option::Option<crate::types::ShipmentInformation>,
    pub(crate) asset_information_list: ::std::option::Option<::std::vec::Vec<crate::types::LineItemAssetInformation>>,
    pub(crate) previous_line_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) previous_order_id: ::std::option::Option<::std::string::String>,
}
impl LineItemBuilder {
    /// <p>The ID of the catalog item.</p>
    pub fn catalog_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the catalog item.</p>
    pub fn set_catalog_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_item_id = input;
        self
    }
    /// <p>The ID of the catalog item.</p>
    pub fn get_catalog_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_item_id
    }
    /// <p>The ID of the line item.</p>
    pub fn line_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.line_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the line item.</p>
    pub fn set_line_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.line_item_id = input;
        self
    }
    /// <p>The ID of the line item.</p>
    pub fn get_line_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.line_item_id
    }
    /// <p>The quantity of the line item.</p>
    pub fn quantity(mut self, input: i32) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The quantity of the line item.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The quantity of the line item.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i32> {
        &self.quantity
    }
    /// <p>The status of the line item.</p>
    pub fn status(mut self, input: crate::types::LineItemStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the line item.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LineItemStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the line item.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LineItemStatus> {
        &self.status
    }
    /// <p>Information about a line item shipment.</p>
    pub fn shipment_information(mut self, input: crate::types::ShipmentInformation) -> Self {
        self.shipment_information = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about a line item shipment.</p>
    pub fn set_shipment_information(mut self, input: ::std::option::Option<crate::types::ShipmentInformation>) -> Self {
        self.shipment_information = input;
        self
    }
    /// <p>Information about a line item shipment.</p>
    pub fn get_shipment_information(&self) -> &::std::option::Option<crate::types::ShipmentInformation> {
        &self.shipment_information
    }
    /// Appends an item to `asset_information_list`.
    ///
    /// To override the contents of this collection use [`set_asset_information_list`](Self::set_asset_information_list).
    ///
    /// <p>Information about assets.</p>
    pub fn asset_information_list(mut self, input: crate::types::LineItemAssetInformation) -> Self {
        let mut v = self.asset_information_list.unwrap_or_default();
        v.push(input);
        self.asset_information_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about assets.</p>
    pub fn set_asset_information_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LineItemAssetInformation>>) -> Self {
        self.asset_information_list = input;
        self
    }
    /// <p>Information about assets.</p>
    pub fn get_asset_information_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LineItemAssetInformation>> {
        &self.asset_information_list
    }
    /// <p>The ID of the previous line item.</p>
    pub fn previous_line_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.previous_line_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the previous line item.</p>
    pub fn set_previous_line_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.previous_line_item_id = input;
        self
    }
    /// <p>The ID of the previous line item.</p>
    pub fn get_previous_line_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.previous_line_item_id
    }
    /// <p>The ID of the previous order.</p>
    pub fn previous_order_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.previous_order_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the previous order.</p>
    pub fn set_previous_order_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.previous_order_id = input;
        self
    }
    /// <p>The ID of the previous order.</p>
    pub fn get_previous_order_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.previous_order_id
    }
    /// Consumes the builder and constructs a [`LineItem`](crate::types::LineItem).
    pub fn build(self) -> crate::types::LineItem {
        crate::types::LineItem {
            catalog_item_id: self.catalog_item_id,
            line_item_id: self.line_item_id,
            quantity: self.quantity,
            status: self.status,
            shipment_information: self.shipment_information,
            asset_information_list: self.asset_information_list,
            previous_line_item_id: self.previous_line_item_id,
            previous_order_id: self.previous_order_id,
        }
    }
}
