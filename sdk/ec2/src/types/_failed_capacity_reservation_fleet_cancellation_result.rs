// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a Capacity Reservation Fleet that could not be cancelled.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FailedCapacityReservationFleetCancellationResult {
    /// <p>The ID of the Capacity Reservation Fleet that could not be cancelled.</p>
    pub capacity_reservation_fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the Capacity Reservation Fleet cancellation error.</p>
    pub cancel_capacity_reservation_fleet_error: ::std::option::Option<crate::types::CancelCapacityReservationFleetError>,
}
impl FailedCapacityReservationFleetCancellationResult {
    /// <p>The ID of the Capacity Reservation Fleet that could not be cancelled.</p>
    pub fn capacity_reservation_fleet_id(&self) -> ::std::option::Option<&str> {
        self.capacity_reservation_fleet_id.as_deref()
    }
    /// <p>Information about the Capacity Reservation Fleet cancellation error.</p>
    pub fn cancel_capacity_reservation_fleet_error(&self) -> ::std::option::Option<&crate::types::CancelCapacityReservationFleetError> {
        self.cancel_capacity_reservation_fleet_error.as_ref()
    }
}
impl FailedCapacityReservationFleetCancellationResult {
    /// Creates a new builder-style object to manufacture [`FailedCapacityReservationFleetCancellationResult`](crate::types::FailedCapacityReservationFleetCancellationResult).
    pub fn builder() -> crate::types::builders::FailedCapacityReservationFleetCancellationResultBuilder {
        crate::types::builders::FailedCapacityReservationFleetCancellationResultBuilder::default()
    }
}

/// A builder for [`FailedCapacityReservationFleetCancellationResult`](crate::types::FailedCapacityReservationFleetCancellationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FailedCapacityReservationFleetCancellationResultBuilder {
    pub(crate) capacity_reservation_fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) cancel_capacity_reservation_fleet_error: ::std::option::Option<crate::types::CancelCapacityReservationFleetError>,
}
impl FailedCapacityReservationFleetCancellationResultBuilder {
    /// <p>The ID of the Capacity Reservation Fleet that could not be cancelled.</p>
    pub fn capacity_reservation_fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Capacity Reservation Fleet that could not be cancelled.</p>
    pub fn set_capacity_reservation_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_id = input;
        self
    }
    /// <p>The ID of the Capacity Reservation Fleet that could not be cancelled.</p>
    pub fn get_capacity_reservation_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_reservation_fleet_id
    }
    /// <p>Information about the Capacity Reservation Fleet cancellation error.</p>
    pub fn cancel_capacity_reservation_fleet_error(mut self, input: crate::types::CancelCapacityReservationFleetError) -> Self {
        self.cancel_capacity_reservation_fleet_error = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the Capacity Reservation Fleet cancellation error.</p>
    pub fn set_cancel_capacity_reservation_fleet_error(
        mut self,
        input: ::std::option::Option<crate::types::CancelCapacityReservationFleetError>,
    ) -> Self {
        self.cancel_capacity_reservation_fleet_error = input;
        self
    }
    /// <p>Information about the Capacity Reservation Fleet cancellation error.</p>
    pub fn get_cancel_capacity_reservation_fleet_error(&self) -> &::std::option::Option<crate::types::CancelCapacityReservationFleetError> {
        &self.cancel_capacity_reservation_fleet_error
    }
    /// Consumes the builder and constructs a [`FailedCapacityReservationFleetCancellationResult`](crate::types::FailedCapacityReservationFleetCancellationResult).
    pub fn build(self) -> crate::types::FailedCapacityReservationFleetCancellationResult {
        crate::types::FailedCapacityReservationFleetCancellationResult {
            capacity_reservation_fleet_id: self.capacity_reservation_fleet_id,
            cancel_capacity_reservation_fleet_error: self.cancel_capacity_reservation_fleet_error,
        }
    }
}
