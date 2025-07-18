// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetHostReservationPurchasePreviewInput {
    /// <p>The IDs of the Dedicated Hosts with which the reservation is associated.</p>
    pub host_id_set: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The offering ID of the reservation.</p>
    pub offering_id: ::std::option::Option<::std::string::String>,
}
impl GetHostReservationPurchasePreviewInput {
    /// <p>The IDs of the Dedicated Hosts with which the reservation is associated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.host_id_set.is_none()`.
    pub fn host_id_set(&self) -> &[::std::string::String] {
        self.host_id_set.as_deref().unwrap_or_default()
    }
    /// <p>The offering ID of the reservation.</p>
    pub fn offering_id(&self) -> ::std::option::Option<&str> {
        self.offering_id.as_deref()
    }
}
impl GetHostReservationPurchasePreviewInput {
    /// Creates a new builder-style object to manufacture [`GetHostReservationPurchasePreviewInput`](crate::operation::get_host_reservation_purchase_preview::GetHostReservationPurchasePreviewInput).
    pub fn builder() -> crate::operation::get_host_reservation_purchase_preview::builders::GetHostReservationPurchasePreviewInputBuilder {
        crate::operation::get_host_reservation_purchase_preview::builders::GetHostReservationPurchasePreviewInputBuilder::default()
    }
}

/// A builder for [`GetHostReservationPurchasePreviewInput`](crate::operation::get_host_reservation_purchase_preview::GetHostReservationPurchasePreviewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetHostReservationPurchasePreviewInputBuilder {
    pub(crate) host_id_set: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) offering_id: ::std::option::Option<::std::string::String>,
}
impl GetHostReservationPurchasePreviewInputBuilder {
    /// Appends an item to `host_id_set`.
    ///
    /// To override the contents of this collection use [`set_host_id_set`](Self::set_host_id_set).
    ///
    /// <p>The IDs of the Dedicated Hosts with which the reservation is associated.</p>
    pub fn host_id_set(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.host_id_set.unwrap_or_default();
        v.push(input.into());
        self.host_id_set = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Dedicated Hosts with which the reservation is associated.</p>
    pub fn set_host_id_set(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.host_id_set = input;
        self
    }
    /// <p>The IDs of the Dedicated Hosts with which the reservation is associated.</p>
    pub fn get_host_id_set(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.host_id_set
    }
    /// <p>The offering ID of the reservation.</p>
    /// This field is required.
    pub fn offering_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.offering_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The offering ID of the reservation.</p>
    pub fn set_offering_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.offering_id = input;
        self
    }
    /// <p>The offering ID of the reservation.</p>
    pub fn get_offering_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.offering_id
    }
    /// Consumes the builder and constructs a [`GetHostReservationPurchasePreviewInput`](crate::operation::get_host_reservation_purchase_preview::GetHostReservationPurchasePreviewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_host_reservation_purchase_preview::GetHostReservationPurchasePreviewInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_host_reservation_purchase_preview::GetHostReservationPurchasePreviewInput {
                host_id_set: self.host_id_set,
                offering_id: self.offering_id,
            },
        )
    }
}
