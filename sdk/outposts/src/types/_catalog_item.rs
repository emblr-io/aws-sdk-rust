// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a catalog item.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CatalogItem {
    /// <p>The ID of the catalog item.</p>
    pub catalog_item_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of a catalog item.</p>
    pub item_status: ::std::option::Option<crate::types::CatalogItemStatus>,
    /// <p>Information about the EC2 capacity of an item.</p>
    pub ec2_capacities: ::std::option::Option<::std::vec::Vec<crate::types::Ec2Capacity>>,
    /// <p>Information about the power draw of an item.</p>
    pub power_kva: ::std::option::Option<f32>,
    /// <p>The weight of the item in pounds.</p>
    pub weight_lbs: ::std::option::Option<i32>,
    /// <p>The uplink speed this catalog item requires for the connection to the Region.</p>
    pub supported_uplink_gbps: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>The supported storage options for the catalog item.</p>
    pub supported_storage: ::std::option::Option<::std::vec::Vec<crate::types::SupportedStorageEnum>>,
}
impl CatalogItem {
    /// <p>The ID of the catalog item.</p>
    pub fn catalog_item_id(&self) -> ::std::option::Option<&str> {
        self.catalog_item_id.as_deref()
    }
    /// <p>The status of a catalog item.</p>
    pub fn item_status(&self) -> ::std::option::Option<&crate::types::CatalogItemStatus> {
        self.item_status.as_ref()
    }
    /// <p>Information about the EC2 capacity of an item.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ec2_capacities.is_none()`.
    pub fn ec2_capacities(&self) -> &[crate::types::Ec2Capacity] {
        self.ec2_capacities.as_deref().unwrap_or_default()
    }
    /// <p>Information about the power draw of an item.</p>
    pub fn power_kva(&self) -> ::std::option::Option<f32> {
        self.power_kva
    }
    /// <p>The weight of the item in pounds.</p>
    pub fn weight_lbs(&self) -> ::std::option::Option<i32> {
        self.weight_lbs
    }
    /// <p>The uplink speed this catalog item requires for the connection to the Region.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_uplink_gbps.is_none()`.
    pub fn supported_uplink_gbps(&self) -> &[i32] {
        self.supported_uplink_gbps.as_deref().unwrap_or_default()
    }
    /// <p>The supported storage options for the catalog item.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_storage.is_none()`.
    pub fn supported_storage(&self) -> &[crate::types::SupportedStorageEnum] {
        self.supported_storage.as_deref().unwrap_or_default()
    }
}
impl CatalogItem {
    /// Creates a new builder-style object to manufacture [`CatalogItem`](crate::types::CatalogItem).
    pub fn builder() -> crate::types::builders::CatalogItemBuilder {
        crate::types::builders::CatalogItemBuilder::default()
    }
}

/// A builder for [`CatalogItem`](crate::types::CatalogItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CatalogItemBuilder {
    pub(crate) catalog_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) item_status: ::std::option::Option<crate::types::CatalogItemStatus>,
    pub(crate) ec2_capacities: ::std::option::Option<::std::vec::Vec<crate::types::Ec2Capacity>>,
    pub(crate) power_kva: ::std::option::Option<f32>,
    pub(crate) weight_lbs: ::std::option::Option<i32>,
    pub(crate) supported_uplink_gbps: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) supported_storage: ::std::option::Option<::std::vec::Vec<crate::types::SupportedStorageEnum>>,
}
impl CatalogItemBuilder {
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
    /// <p>The status of a catalog item.</p>
    pub fn item_status(mut self, input: crate::types::CatalogItemStatus) -> Self {
        self.item_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a catalog item.</p>
    pub fn set_item_status(mut self, input: ::std::option::Option<crate::types::CatalogItemStatus>) -> Self {
        self.item_status = input;
        self
    }
    /// <p>The status of a catalog item.</p>
    pub fn get_item_status(&self) -> &::std::option::Option<crate::types::CatalogItemStatus> {
        &self.item_status
    }
    /// Appends an item to `ec2_capacities`.
    ///
    /// To override the contents of this collection use [`set_ec2_capacities`](Self::set_ec2_capacities).
    ///
    /// <p>Information about the EC2 capacity of an item.</p>
    pub fn ec2_capacities(mut self, input: crate::types::Ec2Capacity) -> Self {
        let mut v = self.ec2_capacities.unwrap_or_default();
        v.push(input);
        self.ec2_capacities = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the EC2 capacity of an item.</p>
    pub fn set_ec2_capacities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Ec2Capacity>>) -> Self {
        self.ec2_capacities = input;
        self
    }
    /// <p>Information about the EC2 capacity of an item.</p>
    pub fn get_ec2_capacities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Ec2Capacity>> {
        &self.ec2_capacities
    }
    /// <p>Information about the power draw of an item.</p>
    pub fn power_kva(mut self, input: f32) -> Self {
        self.power_kva = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the power draw of an item.</p>
    pub fn set_power_kva(mut self, input: ::std::option::Option<f32>) -> Self {
        self.power_kva = input;
        self
    }
    /// <p>Information about the power draw of an item.</p>
    pub fn get_power_kva(&self) -> &::std::option::Option<f32> {
        &self.power_kva
    }
    /// <p>The weight of the item in pounds.</p>
    pub fn weight_lbs(mut self, input: i32) -> Self {
        self.weight_lbs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The weight of the item in pounds.</p>
    pub fn set_weight_lbs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.weight_lbs = input;
        self
    }
    /// <p>The weight of the item in pounds.</p>
    pub fn get_weight_lbs(&self) -> &::std::option::Option<i32> {
        &self.weight_lbs
    }
    /// Appends an item to `supported_uplink_gbps`.
    ///
    /// To override the contents of this collection use [`set_supported_uplink_gbps`](Self::set_supported_uplink_gbps).
    ///
    /// <p>The uplink speed this catalog item requires for the connection to the Region.</p>
    pub fn supported_uplink_gbps(mut self, input: i32) -> Self {
        let mut v = self.supported_uplink_gbps.unwrap_or_default();
        v.push(input);
        self.supported_uplink_gbps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The uplink speed this catalog item requires for the connection to the Region.</p>
    pub fn set_supported_uplink_gbps(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.supported_uplink_gbps = input;
        self
    }
    /// <p>The uplink speed this catalog item requires for the connection to the Region.</p>
    pub fn get_supported_uplink_gbps(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.supported_uplink_gbps
    }
    /// Appends an item to `supported_storage`.
    ///
    /// To override the contents of this collection use [`set_supported_storage`](Self::set_supported_storage).
    ///
    /// <p>The supported storage options for the catalog item.</p>
    pub fn supported_storage(mut self, input: crate::types::SupportedStorageEnum) -> Self {
        let mut v = self.supported_storage.unwrap_or_default();
        v.push(input);
        self.supported_storage = ::std::option::Option::Some(v);
        self
    }
    /// <p>The supported storage options for the catalog item.</p>
    pub fn set_supported_storage(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SupportedStorageEnum>>) -> Self {
        self.supported_storage = input;
        self
    }
    /// <p>The supported storage options for the catalog item.</p>
    pub fn get_supported_storage(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SupportedStorageEnum>> {
        &self.supported_storage
    }
    /// Consumes the builder and constructs a [`CatalogItem`](crate::types::CatalogItem).
    pub fn build(self) -> crate::types::CatalogItem {
        crate::types::CatalogItem {
            catalog_item_id: self.catalog_item_id,
            item_status: self.item_status,
            ec2_capacities: self.ec2_capacities,
            power_kva: self.power_kva,
            weight_lbs: self.weight_lbs,
            supported_uplink_gbps: self.supported_uplink_gbps,
            supported_storage: self.supported_storage,
        }
    }
}
