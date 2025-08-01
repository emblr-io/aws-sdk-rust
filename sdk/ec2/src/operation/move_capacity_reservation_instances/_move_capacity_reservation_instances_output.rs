// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MoveCapacityReservationInstancesOutput {
    /// <p>Information about the source Capacity Reservation.</p>
    pub source_capacity_reservation: ::std::option::Option<crate::types::CapacityReservation>,
    /// <p>Information about the destination Capacity Reservation.</p>
    pub destination_capacity_reservation: ::std::option::Option<crate::types::CapacityReservation>,
    /// <p>The number of instances that were moved from the source Capacity Reservation to the destination Capacity Reservation.</p>
    pub instance_count: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl MoveCapacityReservationInstancesOutput {
    /// <p>Information about the source Capacity Reservation.</p>
    pub fn source_capacity_reservation(&self) -> ::std::option::Option<&crate::types::CapacityReservation> {
        self.source_capacity_reservation.as_ref()
    }
    /// <p>Information about the destination Capacity Reservation.</p>
    pub fn destination_capacity_reservation(&self) -> ::std::option::Option<&crate::types::CapacityReservation> {
        self.destination_capacity_reservation.as_ref()
    }
    /// <p>The number of instances that were moved from the source Capacity Reservation to the destination Capacity Reservation.</p>
    pub fn instance_count(&self) -> ::std::option::Option<i32> {
        self.instance_count
    }
}
impl ::aws_types::request_id::RequestId for MoveCapacityReservationInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl MoveCapacityReservationInstancesOutput {
    /// Creates a new builder-style object to manufacture [`MoveCapacityReservationInstancesOutput`](crate::operation::move_capacity_reservation_instances::MoveCapacityReservationInstancesOutput).
    pub fn builder() -> crate::operation::move_capacity_reservation_instances::builders::MoveCapacityReservationInstancesOutputBuilder {
        crate::operation::move_capacity_reservation_instances::builders::MoveCapacityReservationInstancesOutputBuilder::default()
    }
}

/// A builder for [`MoveCapacityReservationInstancesOutput`](crate::operation::move_capacity_reservation_instances::MoveCapacityReservationInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MoveCapacityReservationInstancesOutputBuilder {
    pub(crate) source_capacity_reservation: ::std::option::Option<crate::types::CapacityReservation>,
    pub(crate) destination_capacity_reservation: ::std::option::Option<crate::types::CapacityReservation>,
    pub(crate) instance_count: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl MoveCapacityReservationInstancesOutputBuilder {
    /// <p>Information about the source Capacity Reservation.</p>
    pub fn source_capacity_reservation(mut self, input: crate::types::CapacityReservation) -> Self {
        self.source_capacity_reservation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the source Capacity Reservation.</p>
    pub fn set_source_capacity_reservation(mut self, input: ::std::option::Option<crate::types::CapacityReservation>) -> Self {
        self.source_capacity_reservation = input;
        self
    }
    /// <p>Information about the source Capacity Reservation.</p>
    pub fn get_source_capacity_reservation(&self) -> &::std::option::Option<crate::types::CapacityReservation> {
        &self.source_capacity_reservation
    }
    /// <p>Information about the destination Capacity Reservation.</p>
    pub fn destination_capacity_reservation(mut self, input: crate::types::CapacityReservation) -> Self {
        self.destination_capacity_reservation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the destination Capacity Reservation.</p>
    pub fn set_destination_capacity_reservation(mut self, input: ::std::option::Option<crate::types::CapacityReservation>) -> Self {
        self.destination_capacity_reservation = input;
        self
    }
    /// <p>Information about the destination Capacity Reservation.</p>
    pub fn get_destination_capacity_reservation(&self) -> &::std::option::Option<crate::types::CapacityReservation> {
        &self.destination_capacity_reservation
    }
    /// <p>The number of instances that were moved from the source Capacity Reservation to the destination Capacity Reservation.</p>
    pub fn instance_count(mut self, input: i32) -> Self {
        self.instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of instances that were moved from the source Capacity Reservation to the destination Capacity Reservation.</p>
    pub fn set_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instance_count = input;
        self
    }
    /// <p>The number of instances that were moved from the source Capacity Reservation to the destination Capacity Reservation.</p>
    pub fn get_instance_count(&self) -> &::std::option::Option<i32> {
        &self.instance_count
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`MoveCapacityReservationInstancesOutput`](crate::operation::move_capacity_reservation_instances::MoveCapacityReservationInstancesOutput).
    pub fn build(self) -> crate::operation::move_capacity_reservation_instances::MoveCapacityReservationInstancesOutput {
        crate::operation::move_capacity_reservation_instances::MoveCapacityReservationInstancesOutput {
            source_capacity_reservation: self.source_capacity_reservation,
            destination_capacity_reservation: self.destination_capacity_reservation,
            instance_count: self.instance_count,
            _request_id: self._request_id,
        }
    }
}
