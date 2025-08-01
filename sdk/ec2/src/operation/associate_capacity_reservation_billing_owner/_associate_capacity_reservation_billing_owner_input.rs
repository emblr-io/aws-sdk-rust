// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateCapacityReservationBillingOwnerInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the Capacity Reservation.</p>
    pub capacity_reservation_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the consumer account to which to assign billing.</p>
    pub unused_reservation_billing_owner_id: ::std::option::Option<::std::string::String>,
}
impl AssociateCapacityReservationBillingOwnerInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the Capacity Reservation.</p>
    pub fn capacity_reservation_id(&self) -> ::std::option::Option<&str> {
        self.capacity_reservation_id.as_deref()
    }
    /// <p>The ID of the consumer account to which to assign billing.</p>
    pub fn unused_reservation_billing_owner_id(&self) -> ::std::option::Option<&str> {
        self.unused_reservation_billing_owner_id.as_deref()
    }
}
impl AssociateCapacityReservationBillingOwnerInput {
    /// Creates a new builder-style object to manufacture [`AssociateCapacityReservationBillingOwnerInput`](crate::operation::associate_capacity_reservation_billing_owner::AssociateCapacityReservationBillingOwnerInput).
    pub fn builder() -> crate::operation::associate_capacity_reservation_billing_owner::builders::AssociateCapacityReservationBillingOwnerInputBuilder
    {
        crate::operation::associate_capacity_reservation_billing_owner::builders::AssociateCapacityReservationBillingOwnerInputBuilder::default()
    }
}

/// A builder for [`AssociateCapacityReservationBillingOwnerInput`](crate::operation::associate_capacity_reservation_billing_owner::AssociateCapacityReservationBillingOwnerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateCapacityReservationBillingOwnerInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) capacity_reservation_id: ::std::option::Option<::std::string::String>,
    pub(crate) unused_reservation_billing_owner_id: ::std::option::Option<::std::string::String>,
}
impl AssociateCapacityReservationBillingOwnerInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The ID of the Capacity Reservation.</p>
    /// This field is required.
    pub fn capacity_reservation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_reservation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Capacity Reservation.</p>
    pub fn set_capacity_reservation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_reservation_id = input;
        self
    }
    /// <p>The ID of the Capacity Reservation.</p>
    pub fn get_capacity_reservation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_reservation_id
    }
    /// <p>The ID of the consumer account to which to assign billing.</p>
    /// This field is required.
    pub fn unused_reservation_billing_owner_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unused_reservation_billing_owner_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the consumer account to which to assign billing.</p>
    pub fn set_unused_reservation_billing_owner_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unused_reservation_billing_owner_id = input;
        self
    }
    /// <p>The ID of the consumer account to which to assign billing.</p>
    pub fn get_unused_reservation_billing_owner_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.unused_reservation_billing_owner_id
    }
    /// Consumes the builder and constructs a [`AssociateCapacityReservationBillingOwnerInput`](crate::operation::associate_capacity_reservation_billing_owner::AssociateCapacityReservationBillingOwnerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_capacity_reservation_billing_owner::AssociateCapacityReservationBillingOwnerInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::associate_capacity_reservation_billing_owner::AssociateCapacityReservationBillingOwnerInput {
                dry_run: self.dry_run,
                capacity_reservation_id: self.capacity_reservation_id,
                unused_reservation_billing_owner_id: self.unused_reservation_billing_owner_id,
            },
        )
    }
}
