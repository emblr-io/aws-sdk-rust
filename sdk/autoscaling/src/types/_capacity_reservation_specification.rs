// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Capacity Reservation preference and targeting options. If you specify <code>open</code> or <code>none</code> for <code>CapacityReservationPreference</code>, do not specify a <code>CapacityReservationTarget</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CapacityReservationSpecification {
    /// <p>The capacity reservation preference. The following options are available:</p>
    /// <ul>
    /// <li>
    /// <p><code>capacity-reservations-only</code> - Auto Scaling will only launch instances into a Capacity Reservation or Capacity Reservation resource group. If capacity isn't available, instances will fail to launch.</p></li>
    /// <li>
    /// <p><code>capacity-reservations-first</code> - Auto Scaling will try to launch instances into a Capacity Reservation or Capacity Reservation resource group first. If capacity isn't available, instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>none</code> - Auto Scaling will not launch instances into a Capacity Reservation. Instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>default</code> - Auto Scaling uses the Capacity Reservation preference from your launch template or an open Capacity Reservation.</p></li>
    /// </ul>
    pub capacity_reservation_preference: ::std::option::Option<crate::types::CapacityReservationPreference>,
    /// <p>Describes a target Capacity Reservation or Capacity Reservation resource group.</p>
    pub capacity_reservation_target: ::std::option::Option<crate::types::CapacityReservationTarget>,
}
impl CapacityReservationSpecification {
    /// <p>The capacity reservation preference. The following options are available:</p>
    /// <ul>
    /// <li>
    /// <p><code>capacity-reservations-only</code> - Auto Scaling will only launch instances into a Capacity Reservation or Capacity Reservation resource group. If capacity isn't available, instances will fail to launch.</p></li>
    /// <li>
    /// <p><code>capacity-reservations-first</code> - Auto Scaling will try to launch instances into a Capacity Reservation or Capacity Reservation resource group first. If capacity isn't available, instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>none</code> - Auto Scaling will not launch instances into a Capacity Reservation. Instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>default</code> - Auto Scaling uses the Capacity Reservation preference from your launch template or an open Capacity Reservation.</p></li>
    /// </ul>
    pub fn capacity_reservation_preference(&self) -> ::std::option::Option<&crate::types::CapacityReservationPreference> {
        self.capacity_reservation_preference.as_ref()
    }
    /// <p>Describes a target Capacity Reservation or Capacity Reservation resource group.</p>
    pub fn capacity_reservation_target(&self) -> ::std::option::Option<&crate::types::CapacityReservationTarget> {
        self.capacity_reservation_target.as_ref()
    }
}
impl CapacityReservationSpecification {
    /// Creates a new builder-style object to manufacture [`CapacityReservationSpecification`](crate::types::CapacityReservationSpecification).
    pub fn builder() -> crate::types::builders::CapacityReservationSpecificationBuilder {
        crate::types::builders::CapacityReservationSpecificationBuilder::default()
    }
}

/// A builder for [`CapacityReservationSpecification`](crate::types::CapacityReservationSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CapacityReservationSpecificationBuilder {
    pub(crate) capacity_reservation_preference: ::std::option::Option<crate::types::CapacityReservationPreference>,
    pub(crate) capacity_reservation_target: ::std::option::Option<crate::types::CapacityReservationTarget>,
}
impl CapacityReservationSpecificationBuilder {
    /// <p>The capacity reservation preference. The following options are available:</p>
    /// <ul>
    /// <li>
    /// <p><code>capacity-reservations-only</code> - Auto Scaling will only launch instances into a Capacity Reservation or Capacity Reservation resource group. If capacity isn't available, instances will fail to launch.</p></li>
    /// <li>
    /// <p><code>capacity-reservations-first</code> - Auto Scaling will try to launch instances into a Capacity Reservation or Capacity Reservation resource group first. If capacity isn't available, instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>none</code> - Auto Scaling will not launch instances into a Capacity Reservation. Instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>default</code> - Auto Scaling uses the Capacity Reservation preference from your launch template or an open Capacity Reservation.</p></li>
    /// </ul>
    pub fn capacity_reservation_preference(mut self, input: crate::types::CapacityReservationPreference) -> Self {
        self.capacity_reservation_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The capacity reservation preference. The following options are available:</p>
    /// <ul>
    /// <li>
    /// <p><code>capacity-reservations-only</code> - Auto Scaling will only launch instances into a Capacity Reservation or Capacity Reservation resource group. If capacity isn't available, instances will fail to launch.</p></li>
    /// <li>
    /// <p><code>capacity-reservations-first</code> - Auto Scaling will try to launch instances into a Capacity Reservation or Capacity Reservation resource group first. If capacity isn't available, instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>none</code> - Auto Scaling will not launch instances into a Capacity Reservation. Instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>default</code> - Auto Scaling uses the Capacity Reservation preference from your launch template or an open Capacity Reservation.</p></li>
    /// </ul>
    pub fn set_capacity_reservation_preference(mut self, input: ::std::option::Option<crate::types::CapacityReservationPreference>) -> Self {
        self.capacity_reservation_preference = input;
        self
    }
    /// <p>The capacity reservation preference. The following options are available:</p>
    /// <ul>
    /// <li>
    /// <p><code>capacity-reservations-only</code> - Auto Scaling will only launch instances into a Capacity Reservation or Capacity Reservation resource group. If capacity isn't available, instances will fail to launch.</p></li>
    /// <li>
    /// <p><code>capacity-reservations-first</code> - Auto Scaling will try to launch instances into a Capacity Reservation or Capacity Reservation resource group first. If capacity isn't available, instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>none</code> - Auto Scaling will not launch instances into a Capacity Reservation. Instances will run in On-Demand capacity.</p></li>
    /// <li>
    /// <p><code>default</code> - Auto Scaling uses the Capacity Reservation preference from your launch template or an open Capacity Reservation.</p></li>
    /// </ul>
    pub fn get_capacity_reservation_preference(&self) -> &::std::option::Option<crate::types::CapacityReservationPreference> {
        &self.capacity_reservation_preference
    }
    /// <p>Describes a target Capacity Reservation or Capacity Reservation resource group.</p>
    pub fn capacity_reservation_target(mut self, input: crate::types::CapacityReservationTarget) -> Self {
        self.capacity_reservation_target = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes a target Capacity Reservation or Capacity Reservation resource group.</p>
    pub fn set_capacity_reservation_target(mut self, input: ::std::option::Option<crate::types::CapacityReservationTarget>) -> Self {
        self.capacity_reservation_target = input;
        self
    }
    /// <p>Describes a target Capacity Reservation or Capacity Reservation resource group.</p>
    pub fn get_capacity_reservation_target(&self) -> &::std::option::Option<crate::types::CapacityReservationTarget> {
        &self.capacity_reservation_target
    }
    /// Consumes the builder and constructs a [`CapacityReservationSpecification`](crate::types::CapacityReservationSpecification).
    pub fn build(self) -> crate::types::CapacityReservationSpecification {
        crate::types::CapacityReservationSpecification {
            capacity_reservation_preference: self.capacity_reservation_preference,
            capacity_reservation_target: self.capacity_reservation_target,
        }
    }
}
