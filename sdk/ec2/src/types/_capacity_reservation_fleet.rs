// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a Capacity Reservation Fleet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CapacityReservationFleet {
    /// <p>The ID of the Capacity Reservation Fleet.</p>
    pub capacity_reservation_fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Capacity Reservation Fleet.</p>
    pub capacity_reservation_fleet_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the Capacity Reservation Fleet. Possible states include:</p>
    /// <ul>
    /// <li>
    /// <p><code>submitted</code> - The Capacity Reservation Fleet request has been submitted and Amazon Elastic Compute Cloud is preparing to create the Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>modifying</code> - The Capacity Reservation Fleet is being modified. The Fleet remains in this state until the modification is complete.</p></li>
    /// <li>
    /// <p><code>active</code> - The Capacity Reservation Fleet has fulfilled its total target capacity and it is attempting to maintain this capacity. The Fleet remains in this state until it is modified or deleted.</p></li>
    /// <li>
    /// <p><code>partially_fulfilled</code> - The Capacity Reservation Fleet has partially fulfilled its total target capacity. There is insufficient Amazon EC2 to fulfill the total target capacity. The Fleet is attempting to asynchronously fulfill its total target capacity.</p></li>
    /// <li>
    /// <p><code>expiring</code> - The Capacity Reservation Fleet has reach its end date and it is in the process of expiring. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>expired</code> - The Capacity Reservation Fleet has reach its end date. The Fleet and its Capacity Reservations are expired. The Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>cancelling</code> - The Capacity Reservation Fleet is in the process of being cancelled. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>cancelled</code> - The Capacity Reservation Fleet has been manually cancelled. The Fleet and its Capacity Reservations are cancelled and the Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>failed</code> - The Capacity Reservation Fleet failed to reserve capacity for the specified instance types.</p></li>
    /// </ul>
    pub state: ::std::option::Option<crate::types::CapacityReservationFleetState>,
    /// <p>The total number of capacity units for which the Capacity Reservation Fleet reserves capacity. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub total_target_capacity: ::std::option::Option<i32>,
    /// <p>The capacity units that have been fulfilled.</p>
    pub total_fulfilled_capacity: ::std::option::Option<f64>,
    /// <p>The tenancy of the Capacity Reservation Fleet. Tenancies include:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservation Fleet is created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub tenancy: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>,
    /// <p>The date and time at which the Capacity Reservation Fleet expires.</p>
    pub end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time at which the Capacity Reservation Fleet was created.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub instance_match_criteria: ::std::option::Option<crate::types::FleetInstanceMatchCriteria>,
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. For more information, see For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy">Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub allocation_strategy: ::std::option::Option<::std::string::String>,
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub instance_type_specifications: ::std::option::Option<::std::vec::Vec<crate::types::FleetCapacityReservation>>,
    /// <p>The tags assigned to the Capacity Reservation Fleet.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CapacityReservationFleet {
    /// <p>The ID of the Capacity Reservation Fleet.</p>
    pub fn capacity_reservation_fleet_id(&self) -> ::std::option::Option<&str> {
        self.capacity_reservation_fleet_id.as_deref()
    }
    /// <p>The ARN of the Capacity Reservation Fleet.</p>
    pub fn capacity_reservation_fleet_arn(&self) -> ::std::option::Option<&str> {
        self.capacity_reservation_fleet_arn.as_deref()
    }
    /// <p>The state of the Capacity Reservation Fleet. Possible states include:</p>
    /// <ul>
    /// <li>
    /// <p><code>submitted</code> - The Capacity Reservation Fleet request has been submitted and Amazon Elastic Compute Cloud is preparing to create the Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>modifying</code> - The Capacity Reservation Fleet is being modified. The Fleet remains in this state until the modification is complete.</p></li>
    /// <li>
    /// <p><code>active</code> - The Capacity Reservation Fleet has fulfilled its total target capacity and it is attempting to maintain this capacity. The Fleet remains in this state until it is modified or deleted.</p></li>
    /// <li>
    /// <p><code>partially_fulfilled</code> - The Capacity Reservation Fleet has partially fulfilled its total target capacity. There is insufficient Amazon EC2 to fulfill the total target capacity. The Fleet is attempting to asynchronously fulfill its total target capacity.</p></li>
    /// <li>
    /// <p><code>expiring</code> - The Capacity Reservation Fleet has reach its end date and it is in the process of expiring. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>expired</code> - The Capacity Reservation Fleet has reach its end date. The Fleet and its Capacity Reservations are expired. The Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>cancelling</code> - The Capacity Reservation Fleet is in the process of being cancelled. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>cancelled</code> - The Capacity Reservation Fleet has been manually cancelled. The Fleet and its Capacity Reservations are cancelled and the Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>failed</code> - The Capacity Reservation Fleet failed to reserve capacity for the specified instance types.</p></li>
    /// </ul>
    pub fn state(&self) -> ::std::option::Option<&crate::types::CapacityReservationFleetState> {
        self.state.as_ref()
    }
    /// <p>The total number of capacity units for which the Capacity Reservation Fleet reserves capacity. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn total_target_capacity(&self) -> ::std::option::Option<i32> {
        self.total_target_capacity
    }
    /// <p>The capacity units that have been fulfilled.</p>
    pub fn total_fulfilled_capacity(&self) -> ::std::option::Option<f64> {
        self.total_fulfilled_capacity
    }
    /// <p>The tenancy of the Capacity Reservation Fleet. Tenancies include:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservation Fleet is created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn tenancy(&self) -> ::std::option::Option<&crate::types::FleetCapacityReservationTenancy> {
        self.tenancy.as_ref()
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires.</p>
    pub fn end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date.as_ref()
    }
    /// <p>The date and time at which the Capacity Reservation Fleet was created.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub fn instance_match_criteria(&self) -> ::std::option::Option<&crate::types::FleetInstanceMatchCriteria> {
        self.instance_match_criteria.as_ref()
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. For more information, see For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy">Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn allocation_strategy(&self) -> ::std::option::Option<&str> {
        self.allocation_strategy.as_deref()
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_type_specifications.is_none()`.
    pub fn instance_type_specifications(&self) -> &[crate::types::FleetCapacityReservation] {
        self.instance_type_specifications.as_deref().unwrap_or_default()
    }
    /// <p>The tags assigned to the Capacity Reservation Fleet.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CapacityReservationFleet {
    /// Creates a new builder-style object to manufacture [`CapacityReservationFleet`](crate::types::CapacityReservationFleet).
    pub fn builder() -> crate::types::builders::CapacityReservationFleetBuilder {
        crate::types::builders::CapacityReservationFleetBuilder::default()
    }
}

/// A builder for [`CapacityReservationFleet`](crate::types::CapacityReservationFleet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CapacityReservationFleetBuilder {
    pub(crate) capacity_reservation_fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) capacity_reservation_fleet_arn: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::CapacityReservationFleetState>,
    pub(crate) total_target_capacity: ::std::option::Option<i32>,
    pub(crate) total_fulfilled_capacity: ::std::option::Option<f64>,
    pub(crate) tenancy: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>,
    pub(crate) end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) instance_match_criteria: ::std::option::Option<crate::types::FleetInstanceMatchCriteria>,
    pub(crate) allocation_strategy: ::std::option::Option<::std::string::String>,
    pub(crate) instance_type_specifications: ::std::option::Option<::std::vec::Vec<crate::types::FleetCapacityReservation>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CapacityReservationFleetBuilder {
    /// <p>The ID of the Capacity Reservation Fleet.</p>
    pub fn capacity_reservation_fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Capacity Reservation Fleet.</p>
    pub fn set_capacity_reservation_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_id = input;
        self
    }
    /// <p>The ID of the Capacity Reservation Fleet.</p>
    pub fn get_capacity_reservation_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_reservation_fleet_id
    }
    /// <p>The ARN of the Capacity Reservation Fleet.</p>
    pub fn capacity_reservation_fleet_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Capacity Reservation Fleet.</p>
    pub fn set_capacity_reservation_fleet_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_reservation_fleet_arn = input;
        self
    }
    /// <p>The ARN of the Capacity Reservation Fleet.</p>
    pub fn get_capacity_reservation_fleet_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_reservation_fleet_arn
    }
    /// <p>The state of the Capacity Reservation Fleet. Possible states include:</p>
    /// <ul>
    /// <li>
    /// <p><code>submitted</code> - The Capacity Reservation Fleet request has been submitted and Amazon Elastic Compute Cloud is preparing to create the Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>modifying</code> - The Capacity Reservation Fleet is being modified. The Fleet remains in this state until the modification is complete.</p></li>
    /// <li>
    /// <p><code>active</code> - The Capacity Reservation Fleet has fulfilled its total target capacity and it is attempting to maintain this capacity. The Fleet remains in this state until it is modified or deleted.</p></li>
    /// <li>
    /// <p><code>partially_fulfilled</code> - The Capacity Reservation Fleet has partially fulfilled its total target capacity. There is insufficient Amazon EC2 to fulfill the total target capacity. The Fleet is attempting to asynchronously fulfill its total target capacity.</p></li>
    /// <li>
    /// <p><code>expiring</code> - The Capacity Reservation Fleet has reach its end date and it is in the process of expiring. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>expired</code> - The Capacity Reservation Fleet has reach its end date. The Fleet and its Capacity Reservations are expired. The Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>cancelling</code> - The Capacity Reservation Fleet is in the process of being cancelled. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>cancelled</code> - The Capacity Reservation Fleet has been manually cancelled. The Fleet and its Capacity Reservations are cancelled and the Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>failed</code> - The Capacity Reservation Fleet failed to reserve capacity for the specified instance types.</p></li>
    /// </ul>
    pub fn state(mut self, input: crate::types::CapacityReservationFleetState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the Capacity Reservation Fleet. Possible states include:</p>
    /// <ul>
    /// <li>
    /// <p><code>submitted</code> - The Capacity Reservation Fleet request has been submitted and Amazon Elastic Compute Cloud is preparing to create the Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>modifying</code> - The Capacity Reservation Fleet is being modified. The Fleet remains in this state until the modification is complete.</p></li>
    /// <li>
    /// <p><code>active</code> - The Capacity Reservation Fleet has fulfilled its total target capacity and it is attempting to maintain this capacity. The Fleet remains in this state until it is modified or deleted.</p></li>
    /// <li>
    /// <p><code>partially_fulfilled</code> - The Capacity Reservation Fleet has partially fulfilled its total target capacity. There is insufficient Amazon EC2 to fulfill the total target capacity. The Fleet is attempting to asynchronously fulfill its total target capacity.</p></li>
    /// <li>
    /// <p><code>expiring</code> - The Capacity Reservation Fleet has reach its end date and it is in the process of expiring. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>expired</code> - The Capacity Reservation Fleet has reach its end date. The Fleet and its Capacity Reservations are expired. The Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>cancelling</code> - The Capacity Reservation Fleet is in the process of being cancelled. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>cancelled</code> - The Capacity Reservation Fleet has been manually cancelled. The Fleet and its Capacity Reservations are cancelled and the Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>failed</code> - The Capacity Reservation Fleet failed to reserve capacity for the specified instance types.</p></li>
    /// </ul>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::CapacityReservationFleetState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the Capacity Reservation Fleet. Possible states include:</p>
    /// <ul>
    /// <li>
    /// <p><code>submitted</code> - The Capacity Reservation Fleet request has been submitted and Amazon Elastic Compute Cloud is preparing to create the Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>modifying</code> - The Capacity Reservation Fleet is being modified. The Fleet remains in this state until the modification is complete.</p></li>
    /// <li>
    /// <p><code>active</code> - The Capacity Reservation Fleet has fulfilled its total target capacity and it is attempting to maintain this capacity. The Fleet remains in this state until it is modified or deleted.</p></li>
    /// <li>
    /// <p><code>partially_fulfilled</code> - The Capacity Reservation Fleet has partially fulfilled its total target capacity. There is insufficient Amazon EC2 to fulfill the total target capacity. The Fleet is attempting to asynchronously fulfill its total target capacity.</p></li>
    /// <li>
    /// <p><code>expiring</code> - The Capacity Reservation Fleet has reach its end date and it is in the process of expiring. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>expired</code> - The Capacity Reservation Fleet has reach its end date. The Fleet and its Capacity Reservations are expired. The Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>cancelling</code> - The Capacity Reservation Fleet is in the process of being cancelled. One or more of its Capacity reservations might still be active.</p></li>
    /// <li>
    /// <p><code>cancelled</code> - The Capacity Reservation Fleet has been manually cancelled. The Fleet and its Capacity Reservations are cancelled and the Fleet can't create new Capacity Reservations.</p></li>
    /// <li>
    /// <p><code>failed</code> - The Capacity Reservation Fleet failed to reserve capacity for the specified instance types.</p></li>
    /// </ul>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::CapacityReservationFleetState> {
        &self.state
    }
    /// <p>The total number of capacity units for which the Capacity Reservation Fleet reserves capacity. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn total_target_capacity(mut self, input: i32) -> Self {
        self.total_target_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of capacity units for which the Capacity Reservation Fleet reserves capacity. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_total_target_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_target_capacity = input;
        self
    }
    /// <p>The total number of capacity units for which the Capacity Reservation Fleet reserves capacity. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_total_target_capacity(&self) -> &::std::option::Option<i32> {
        &self.total_target_capacity
    }
    /// <p>The capacity units that have been fulfilled.</p>
    pub fn total_fulfilled_capacity(mut self, input: f64) -> Self {
        self.total_fulfilled_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The capacity units that have been fulfilled.</p>
    pub fn set_total_fulfilled_capacity(mut self, input: ::std::option::Option<f64>) -> Self {
        self.total_fulfilled_capacity = input;
        self
    }
    /// <p>The capacity units that have been fulfilled.</p>
    pub fn get_total_fulfilled_capacity(&self) -> &::std::option::Option<f64> {
        &self.total_fulfilled_capacity
    }
    /// <p>The tenancy of the Capacity Reservation Fleet. Tenancies include:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservation Fleet is created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn tenancy(mut self, input: crate::types::FleetCapacityReservationTenancy) -> Self {
        self.tenancy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tenancy of the Capacity Reservation Fleet. Tenancies include:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservation Fleet is created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn set_tenancy(mut self, input: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>) -> Self {
        self.tenancy = input;
        self
    }
    /// <p>The tenancy of the Capacity Reservation Fleet. Tenancies include:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservation Fleet is created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn get_tenancy(&self) -> &::std::option::Option<crate::types::FleetCapacityReservationTenancy> {
        &self.tenancy
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires.</p>
    pub fn end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date
    }
    /// <p>The date and time at which the Capacity Reservation Fleet was created.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub fn instance_match_criteria(mut self, input: crate::types::FleetInstanceMatchCriteria) -> Self {
        self.instance_match_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub fn set_instance_match_criteria(mut self, input: ::std::option::Option<crate::types::FleetInstanceMatchCriteria>) -> Self {
        self.instance_match_criteria = input;
        self
    }
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub fn get_instance_match_criteria(&self) -> &::std::option::Option<crate::types::FleetInstanceMatchCriteria> {
        &self.instance_match_criteria
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. For more information, see For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy">Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn allocation_strategy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allocation_strategy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. For more information, see For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy">Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_allocation_strategy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allocation_strategy = input;
        self
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. For more information, see For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy">Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_allocation_strategy(&self) -> &::std::option::Option<::std::string::String> {
        &self.allocation_strategy
    }
    /// Appends an item to `instance_type_specifications`.
    ///
    /// To override the contents of this collection use [`set_instance_type_specifications`](Self::set_instance_type_specifications).
    ///
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn instance_type_specifications(mut self, input: crate::types::FleetCapacityReservation) -> Self {
        let mut v = self.instance_type_specifications.unwrap_or_default();
        v.push(input);
        self.instance_type_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn set_instance_type_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FleetCapacityReservation>>) -> Self {
        self.instance_type_specifications = input;
        self
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn get_instance_type_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FleetCapacityReservation>> {
        &self.instance_type_specifications
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the Capacity Reservation Fleet.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags assigned to the Capacity Reservation Fleet.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the Capacity Reservation Fleet.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CapacityReservationFleet`](crate::types::CapacityReservationFleet).
    pub fn build(self) -> crate::types::CapacityReservationFleet {
        crate::types::CapacityReservationFleet {
            capacity_reservation_fleet_id: self.capacity_reservation_fleet_id,
            capacity_reservation_fleet_arn: self.capacity_reservation_fleet_arn,
            state: self.state,
            total_target_capacity: self.total_target_capacity,
            total_fulfilled_capacity: self.total_fulfilled_capacity,
            tenancy: self.tenancy,
            end_date: self.end_date,
            create_time: self.create_time,
            instance_match_criteria: self.instance_match_criteria,
            allocation_strategy: self.allocation_strategy,
            instance_type_specifications: self.instance_type_specifications,
            tags: self.tags,
        }
    }
}
