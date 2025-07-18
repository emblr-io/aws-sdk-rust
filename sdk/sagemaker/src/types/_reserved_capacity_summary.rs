// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of a reserved capacity for the training plan.</p>
/// <p>For more information about how to reserve GPU capacity for your SageMaker HyperPod clusters using Amazon SageMaker Training Plan, see <code> <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreateTrainingPlan.html">CreateTrainingPlan</a> </code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReservedCapacitySummary {
    /// <p>The Amazon Resource Name (ARN); of the reserved capacity.</p>
    pub reserved_capacity_arn: ::std::option::Option<::std::string::String>,
    /// <p>The instance type for the reserved capacity.</p>
    pub instance_type: ::std::option::Option<crate::types::ReservedCapacityInstanceType>,
    /// <p>The total number of instances in the reserved capacity.</p>
    pub total_instance_count: ::std::option::Option<i32>,
    /// <p>The current status of the reserved capacity.</p>
    pub status: ::std::option::Option<crate::types::ReservedCapacityStatus>,
    /// <p>The availability zone for the reserved capacity.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The number of whole hours in the total duration for this reserved capacity.</p>
    pub duration_hours: ::std::option::Option<i64>,
    /// <p>The additional minutes beyond whole hours in the total duration for this reserved capacity.</p>
    pub duration_minutes: ::std::option::Option<i64>,
    /// <p>The start time of the reserved capacity.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end time of the reserved capacity.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReservedCapacitySummary {
    /// <p>The Amazon Resource Name (ARN); of the reserved capacity.</p>
    pub fn reserved_capacity_arn(&self) -> ::std::option::Option<&str> {
        self.reserved_capacity_arn.as_deref()
    }
    /// <p>The instance type for the reserved capacity.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&crate::types::ReservedCapacityInstanceType> {
        self.instance_type.as_ref()
    }
    /// <p>The total number of instances in the reserved capacity.</p>
    pub fn total_instance_count(&self) -> ::std::option::Option<i32> {
        self.total_instance_count
    }
    /// <p>The current status of the reserved capacity.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ReservedCapacityStatus> {
        self.status.as_ref()
    }
    /// <p>The availability zone for the reserved capacity.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The number of whole hours in the total duration for this reserved capacity.</p>
    pub fn duration_hours(&self) -> ::std::option::Option<i64> {
        self.duration_hours
    }
    /// <p>The additional minutes beyond whole hours in the total duration for this reserved capacity.</p>
    pub fn duration_minutes(&self) -> ::std::option::Option<i64> {
        self.duration_minutes
    }
    /// <p>The start time of the reserved capacity.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end time of the reserved capacity.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl ReservedCapacitySummary {
    /// Creates a new builder-style object to manufacture [`ReservedCapacitySummary`](crate::types::ReservedCapacitySummary).
    pub fn builder() -> crate::types::builders::ReservedCapacitySummaryBuilder {
        crate::types::builders::ReservedCapacitySummaryBuilder::default()
    }
}

/// A builder for [`ReservedCapacitySummary`](crate::types::ReservedCapacitySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReservedCapacitySummaryBuilder {
    pub(crate) reserved_capacity_arn: ::std::option::Option<::std::string::String>,
    pub(crate) instance_type: ::std::option::Option<crate::types::ReservedCapacityInstanceType>,
    pub(crate) total_instance_count: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::ReservedCapacityStatus>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) duration_hours: ::std::option::Option<i64>,
    pub(crate) duration_minutes: ::std::option::Option<i64>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReservedCapacitySummaryBuilder {
    /// <p>The Amazon Resource Name (ARN); of the reserved capacity.</p>
    /// This field is required.
    pub fn reserved_capacity_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reserved_capacity_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN); of the reserved capacity.</p>
    pub fn set_reserved_capacity_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reserved_capacity_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN); of the reserved capacity.</p>
    pub fn get_reserved_capacity_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.reserved_capacity_arn
    }
    /// <p>The instance type for the reserved capacity.</p>
    /// This field is required.
    pub fn instance_type(mut self, input: crate::types::ReservedCapacityInstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type for the reserved capacity.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::ReservedCapacityInstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type for the reserved capacity.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::ReservedCapacityInstanceType> {
        &self.instance_type
    }
    /// <p>The total number of instances in the reserved capacity.</p>
    /// This field is required.
    pub fn total_instance_count(mut self, input: i32) -> Self {
        self.total_instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of instances in the reserved capacity.</p>
    pub fn set_total_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_instance_count = input;
        self
    }
    /// <p>The total number of instances in the reserved capacity.</p>
    pub fn get_total_instance_count(&self) -> &::std::option::Option<i32> {
        &self.total_instance_count
    }
    /// <p>The current status of the reserved capacity.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ReservedCapacityStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the reserved capacity.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ReservedCapacityStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the reserved capacity.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ReservedCapacityStatus> {
        &self.status
    }
    /// <p>The availability zone for the reserved capacity.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The availability zone for the reserved capacity.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The availability zone for the reserved capacity.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The number of whole hours in the total duration for this reserved capacity.</p>
    pub fn duration_hours(mut self, input: i64) -> Self {
        self.duration_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of whole hours in the total duration for this reserved capacity.</p>
    pub fn set_duration_hours(mut self, input: ::std::option::Option<i64>) -> Self {
        self.duration_hours = input;
        self
    }
    /// <p>The number of whole hours in the total duration for this reserved capacity.</p>
    pub fn get_duration_hours(&self) -> &::std::option::Option<i64> {
        &self.duration_hours
    }
    /// <p>The additional minutes beyond whole hours in the total duration for this reserved capacity.</p>
    pub fn duration_minutes(mut self, input: i64) -> Self {
        self.duration_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The additional minutes beyond whole hours in the total duration for this reserved capacity.</p>
    pub fn set_duration_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.duration_minutes = input;
        self
    }
    /// <p>The additional minutes beyond whole hours in the total duration for this reserved capacity.</p>
    pub fn get_duration_minutes(&self) -> &::std::option::Option<i64> {
        &self.duration_minutes
    }
    /// <p>The start time of the reserved capacity.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of the reserved capacity.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of the reserved capacity.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end time of the reserved capacity.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time of the reserved capacity.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time of the reserved capacity.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`ReservedCapacitySummary`](crate::types::ReservedCapacitySummary).
    pub fn build(self) -> crate::types::ReservedCapacitySummary {
        crate::types::ReservedCapacitySummary {
            reserved_capacity_arn: self.reserved_capacity_arn,
            instance_type: self.instance_type,
            total_instance_count: self.total_instance_count,
            status: self.status,
            availability_zone: self.availability_zone,
            duration_hours: self.duration_hours,
            duration_minutes: self.duration_minutes,
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
}
