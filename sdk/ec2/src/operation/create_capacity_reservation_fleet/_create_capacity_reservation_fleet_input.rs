// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCapacityReservationFleetInput {
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. Currently, only the <code>prioritized</code> allocation strategy is supported. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy"> Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <p>Valid values: <code>prioritized</code></p>
    pub allocation_strategy: ::std::option::Option<::std::string::String>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensure Idempotency</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub instance_type_specifications: ::std::option::Option<::std::vec::Vec<crate::types::ReservationFleetInstanceSpecification>>,
    /// <p>Indicates the tenancy of the Capacity Reservation Fleet. All Capacity Reservations in the Fleet inherit this tenancy. The Capacity Reservation Fleet can have one of the following tenancy settings:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservations are created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub tenancy: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>,
    /// <p>The total number of capacity units to be reserved by the Capacity Reservation Fleet. This value, together with the instance type weights that you assign to each instance type used by the Fleet determine the number of instances for which the Fleet reserves capacity. Both values are based on units that make sense for your workload. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub total_target_capacity: ::std::option::Option<i32>,
    /// <p>The date and time at which the Capacity Reservation Fleet expires. When the Capacity Reservation Fleet expires, its state changes to <code>expired</code> and all of the Capacity Reservations in the Fleet expire.</p>
    /// <p>The Capacity Reservation Fleet expires within an hour after the specified time. For example, if you specify <code>5/31/2019</code>, <code>13:30:55</code>, the Capacity Reservation Fleet is guaranteed to expire between <code>13:30:55</code> and <code>14:30:55</code> on <code>5/31/2019</code>.</p>
    pub end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub instance_match_criteria: ::std::option::Option<crate::types::FleetInstanceMatchCriteria>,
    /// <p>The tags to assign to the Capacity Reservation Fleet. The tags are automatically assigned to the Capacity Reservations in the Fleet.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CreateCapacityReservationFleetInput {
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. Currently, only the <code>prioritized</code> allocation strategy is supported. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy"> Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <p>Valid values: <code>prioritized</code></p>
    pub fn allocation_strategy(&self) -> ::std::option::Option<&str> {
        self.allocation_strategy.as_deref()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensure Idempotency</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_type_specifications.is_none()`.
    pub fn instance_type_specifications(&self) -> &[crate::types::ReservationFleetInstanceSpecification] {
        self.instance_type_specifications.as_deref().unwrap_or_default()
    }
    /// <p>Indicates the tenancy of the Capacity Reservation Fleet. All Capacity Reservations in the Fleet inherit this tenancy. The Capacity Reservation Fleet can have one of the following tenancy settings:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservations are created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn tenancy(&self) -> ::std::option::Option<&crate::types::FleetCapacityReservationTenancy> {
        self.tenancy.as_ref()
    }
    /// <p>The total number of capacity units to be reserved by the Capacity Reservation Fleet. This value, together with the instance type weights that you assign to each instance type used by the Fleet determine the number of instances for which the Fleet reserves capacity. Both values are based on units that make sense for your workload. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn total_target_capacity(&self) -> ::std::option::Option<i32> {
        self.total_target_capacity
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires. When the Capacity Reservation Fleet expires, its state changes to <code>expired</code> and all of the Capacity Reservations in the Fleet expire.</p>
    /// <p>The Capacity Reservation Fleet expires within an hour after the specified time. For example, if you specify <code>5/31/2019</code>, <code>13:30:55</code>, the Capacity Reservation Fleet is guaranteed to expire between <code>13:30:55</code> and <code>14:30:55</code> on <code>5/31/2019</code>.</p>
    pub fn end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date.as_ref()
    }
    /// <p>Indicates the type of instance launches that the Capacity Reservation Fleet accepts. All Capacity Reservations in the Fleet inherit this instance matching criteria.</p>
    /// <p>Currently, Capacity Reservation Fleets support <code>open</code> instance matching criteria only. This means that instances that have matching attributes (instance type, platform, and Availability Zone) run in the Capacity Reservations automatically. Instances do not need to explicitly target a Capacity Reservation Fleet to use its reserved capacity.</p>
    pub fn instance_match_criteria(&self) -> ::std::option::Option<&crate::types::FleetInstanceMatchCriteria> {
        self.instance_match_criteria.as_ref()
    }
    /// <p>The tags to assign to the Capacity Reservation Fleet. The tags are automatically assigned to the Capacity Reservations in the Fleet.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CreateCapacityReservationFleetInput {
    /// Creates a new builder-style object to manufacture [`CreateCapacityReservationFleetInput`](crate::operation::create_capacity_reservation_fleet::CreateCapacityReservationFleetInput).
    pub fn builder() -> crate::operation::create_capacity_reservation_fleet::builders::CreateCapacityReservationFleetInputBuilder {
        crate::operation::create_capacity_reservation_fleet::builders::CreateCapacityReservationFleetInputBuilder::default()
    }
}

/// A builder for [`CreateCapacityReservationFleetInput`](crate::operation::create_capacity_reservation_fleet::CreateCapacityReservationFleetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCapacityReservationFleetInputBuilder {
    pub(crate) allocation_strategy: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) instance_type_specifications: ::std::option::Option<::std::vec::Vec<crate::types::ReservationFleetInstanceSpecification>>,
    pub(crate) tenancy: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>,
    pub(crate) total_target_capacity: ::std::option::Option<i32>,
    pub(crate) end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) instance_match_criteria: ::std::option::Option<crate::types::FleetInstanceMatchCriteria>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CreateCapacityReservationFleetInputBuilder {
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. Currently, only the <code>prioritized</code> allocation strategy is supported. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy"> Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <p>Valid values: <code>prioritized</code></p>
    pub fn allocation_strategy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allocation_strategy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. Currently, only the <code>prioritized</code> allocation strategy is supported. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy"> Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <p>Valid values: <code>prioritized</code></p>
    pub fn set_allocation_strategy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allocation_strategy = input;
        self
    }
    /// <p>The strategy used by the Capacity Reservation Fleet to determine which of the specified instance types to use. Currently, only the <code>prioritized</code> allocation strategy is supported. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#allocation-strategy"> Allocation strategy</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <p>Valid values: <code>prioritized</code></p>
    pub fn get_allocation_strategy(&self) -> &::std::option::Option<::std::string::String> {
        &self.allocation_strategy
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensure Idempotency</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensure Idempotency</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensure Idempotency</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `instance_type_specifications`.
    ///
    /// To override the contents of this collection use [`set_instance_type_specifications`](Self::set_instance_type_specifications).
    ///
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn instance_type_specifications(mut self, input: crate::types::ReservationFleetInstanceSpecification) -> Self {
        let mut v = self.instance_type_specifications.unwrap_or_default();
        v.push(input);
        self.instance_type_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn set_instance_type_specifications(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ReservationFleetInstanceSpecification>>,
    ) -> Self {
        self.instance_type_specifications = input;
        self
    }
    /// <p>Information about the instance types for which to reserve the capacity.</p>
    pub fn get_instance_type_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReservationFleetInstanceSpecification>> {
        &self.instance_type_specifications
    }
    /// <p>Indicates the tenancy of the Capacity Reservation Fleet. All Capacity Reservations in the Fleet inherit this tenancy. The Capacity Reservation Fleet can have one of the following tenancy settings:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservations are created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn tenancy(mut self, input: crate::types::FleetCapacityReservationTenancy) -> Self {
        self.tenancy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the tenancy of the Capacity Reservation Fleet. All Capacity Reservations in the Fleet inherit this tenancy. The Capacity Reservation Fleet can have one of the following tenancy settings:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservations are created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn set_tenancy(mut self, input: ::std::option::Option<crate::types::FleetCapacityReservationTenancy>) -> Self {
        self.tenancy = input;
        self
    }
    /// <p>Indicates the tenancy of the Capacity Reservation Fleet. All Capacity Reservations in the Fleet inherit this tenancy. The Capacity Reservation Fleet can have one of the following tenancy settings:</p>
    /// <ul>
    /// <li>
    /// <p><code>default</code> - The Capacity Reservation Fleet is created on hardware that is shared with other Amazon Web Services accounts.</p></li>
    /// <li>
    /// <p><code>dedicated</code> - The Capacity Reservations are created on single-tenant hardware that is dedicated to a single Amazon Web Services account.</p></li>
    /// </ul>
    pub fn get_tenancy(&self) -> &::std::option::Option<crate::types::FleetCapacityReservationTenancy> {
        &self.tenancy
    }
    /// <p>The total number of capacity units to be reserved by the Capacity Reservation Fleet. This value, together with the instance type weights that you assign to each instance type used by the Fleet determine the number of instances for which the Fleet reserves capacity. Both values are based on units that make sense for your workload. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// This field is required.
    pub fn total_target_capacity(mut self, input: i32) -> Self {
        self.total_target_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of capacity units to be reserved by the Capacity Reservation Fleet. This value, together with the instance type weights that you assign to each instance type used by the Fleet determine the number of instances for which the Fleet reserves capacity. Both values are based on units that make sense for your workload. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_total_target_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_target_capacity = input;
        self
    }
    /// <p>The total number of capacity units to be reserved by the Capacity Reservation Fleet. This value, together with the instance type weights that you assign to each instance type used by the Fleet determine the number of instances for which the Fleet reserves capacity. Both values are based on units that make sense for your workload. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/crfleet-concepts.html#target-capacity">Total target capacity</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_total_target_capacity(&self) -> &::std::option::Option<i32> {
        &self.total_target_capacity
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires. When the Capacity Reservation Fleet expires, its state changes to <code>expired</code> and all of the Capacity Reservations in the Fleet expire.</p>
    /// <p>The Capacity Reservation Fleet expires within an hour after the specified time. For example, if you specify <code>5/31/2019</code>, <code>13:30:55</code>, the Capacity Reservation Fleet is guaranteed to expire between <code>13:30:55</code> and <code>14:30:55</code> on <code>5/31/2019</code>.</p>
    pub fn end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires. When the Capacity Reservation Fleet expires, its state changes to <code>expired</code> and all of the Capacity Reservations in the Fleet expire.</p>
    /// <p>The Capacity Reservation Fleet expires within an hour after the specified time. For example, if you specify <code>5/31/2019</code>, <code>13:30:55</code>, the Capacity Reservation Fleet is guaranteed to expire between <code>13:30:55</code> and <code>14:30:55</code> on <code>5/31/2019</code>.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>The date and time at which the Capacity Reservation Fleet expires. When the Capacity Reservation Fleet expires, its state changes to <code>expired</code> and all of the Capacity Reservations in the Fleet expire.</p>
    /// <p>The Capacity Reservation Fleet expires within an hour after the specified time. For example, if you specify <code>5/31/2019</code>, <code>13:30:55</code>, the Capacity Reservation Fleet is guaranteed to expire between <code>13:30:55</code> and <code>14:30:55</code> on <code>5/31/2019</code>.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date
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
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>The tags to assign to the Capacity Reservation Fleet. The tags are automatically assigned to the Capacity Reservations in the Fleet.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to assign to the Capacity Reservation Fleet. The tags are automatically assigned to the Capacity Reservations in the Fleet.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>The tags to assign to the Capacity Reservation Fleet. The tags are automatically assigned to the Capacity Reservations in the Fleet.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
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
    /// Consumes the builder and constructs a [`CreateCapacityReservationFleetInput`](crate::operation::create_capacity_reservation_fleet::CreateCapacityReservationFleetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_capacity_reservation_fleet::CreateCapacityReservationFleetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_capacity_reservation_fleet::CreateCapacityReservationFleetInput {
            allocation_strategy: self.allocation_strategy,
            client_token: self.client_token,
            instance_type_specifications: self.instance_type_specifications,
            tenancy: self.tenancy,
            total_target_capacity: self.total_target_capacity,
            end_date: self.end_date,
            instance_match_criteria: self.instance_match_criteria,
            tag_specifications: self.tag_specifications,
            dry_run: self.dry_run,
        })
    }
}
