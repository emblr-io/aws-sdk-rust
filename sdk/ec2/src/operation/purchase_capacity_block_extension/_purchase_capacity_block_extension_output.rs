// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PurchaseCapacityBlockExtensionOutput {
    /// <p>The purchased Capacity Block extensions.</p>
    pub capacity_block_extensions: ::std::option::Option<::std::vec::Vec<crate::types::CapacityBlockExtension>>,
    _request_id: Option<String>,
}
impl PurchaseCapacityBlockExtensionOutput {
    /// <p>The purchased Capacity Block extensions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capacity_block_extensions.is_none()`.
    pub fn capacity_block_extensions(&self) -> &[crate::types::CapacityBlockExtension] {
        self.capacity_block_extensions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for PurchaseCapacityBlockExtensionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PurchaseCapacityBlockExtensionOutput {
    /// Creates a new builder-style object to manufacture [`PurchaseCapacityBlockExtensionOutput`](crate::operation::purchase_capacity_block_extension::PurchaseCapacityBlockExtensionOutput).
    pub fn builder() -> crate::operation::purchase_capacity_block_extension::builders::PurchaseCapacityBlockExtensionOutputBuilder {
        crate::operation::purchase_capacity_block_extension::builders::PurchaseCapacityBlockExtensionOutputBuilder::default()
    }
}

/// A builder for [`PurchaseCapacityBlockExtensionOutput`](crate::operation::purchase_capacity_block_extension::PurchaseCapacityBlockExtensionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PurchaseCapacityBlockExtensionOutputBuilder {
    pub(crate) capacity_block_extensions: ::std::option::Option<::std::vec::Vec<crate::types::CapacityBlockExtension>>,
    _request_id: Option<String>,
}
impl PurchaseCapacityBlockExtensionOutputBuilder {
    /// Appends an item to `capacity_block_extensions`.
    ///
    /// To override the contents of this collection use [`set_capacity_block_extensions`](Self::set_capacity_block_extensions).
    ///
    /// <p>The purchased Capacity Block extensions.</p>
    pub fn capacity_block_extensions(mut self, input: crate::types::CapacityBlockExtension) -> Self {
        let mut v = self.capacity_block_extensions.unwrap_or_default();
        v.push(input);
        self.capacity_block_extensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The purchased Capacity Block extensions.</p>
    pub fn set_capacity_block_extensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CapacityBlockExtension>>) -> Self {
        self.capacity_block_extensions = input;
        self
    }
    /// <p>The purchased Capacity Block extensions.</p>
    pub fn get_capacity_block_extensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CapacityBlockExtension>> {
        &self.capacity_block_extensions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PurchaseCapacityBlockExtensionOutput`](crate::operation::purchase_capacity_block_extension::PurchaseCapacityBlockExtensionOutput).
    pub fn build(self) -> crate::operation::purchase_capacity_block_extension::PurchaseCapacityBlockExtensionOutput {
        crate::operation::purchase_capacity_block_extension::PurchaseCapacityBlockExtensionOutput {
            capacity_block_extensions: self.capacity_block_extensions,
            _request_id: self._request_id,
        }
    }
}
