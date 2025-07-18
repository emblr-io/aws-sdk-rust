// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFleetCapacityInput {
    /// <p>A unique identifier for the fleet to update capacity settings for. You can use either the fleet ID or ARN value.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The number of Amazon EC2 instances you want to maintain in the specified fleet location. This value must fall between the minimum and maximum size limits. Changes in desired instance value can take up to 1 minute to be reflected when viewing the fleet's capacity settings.</p>
    pub desired_instances: ::std::option::Option<i32>,
    /// <p>The minimum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 0.</p>
    pub min_size: ::std::option::Option<i32>,
    /// <p>The maximum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 1.</p>
    pub max_size: ::std::option::Option<i32>,
    /// <p>The name of a remote location to update fleet capacity settings for, in the form of an Amazon Web Services Region code such as <code>us-west-2</code>.</p>
    pub location: ::std::option::Option<::std::string::String>,
}
impl UpdateFleetCapacityInput {
    /// <p>A unique identifier for the fleet to update capacity settings for. You can use either the fleet ID or ARN value.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>The number of Amazon EC2 instances you want to maintain in the specified fleet location. This value must fall between the minimum and maximum size limits. Changes in desired instance value can take up to 1 minute to be reflected when viewing the fleet's capacity settings.</p>
    pub fn desired_instances(&self) -> ::std::option::Option<i32> {
        self.desired_instances
    }
    /// <p>The minimum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 0.</p>
    pub fn min_size(&self) -> ::std::option::Option<i32> {
        self.min_size
    }
    /// <p>The maximum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 1.</p>
    pub fn max_size(&self) -> ::std::option::Option<i32> {
        self.max_size
    }
    /// <p>The name of a remote location to update fleet capacity settings for, in the form of an Amazon Web Services Region code such as <code>us-west-2</code>.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
}
impl UpdateFleetCapacityInput {
    /// Creates a new builder-style object to manufacture [`UpdateFleetCapacityInput`](crate::operation::update_fleet_capacity::UpdateFleetCapacityInput).
    pub fn builder() -> crate::operation::update_fleet_capacity::builders::UpdateFleetCapacityInputBuilder {
        crate::operation::update_fleet_capacity::builders::UpdateFleetCapacityInputBuilder::default()
    }
}

/// A builder for [`UpdateFleetCapacityInput`](crate::operation::update_fleet_capacity::UpdateFleetCapacityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFleetCapacityInputBuilder {
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) desired_instances: ::std::option::Option<i32>,
    pub(crate) min_size: ::std::option::Option<i32>,
    pub(crate) max_size: ::std::option::Option<i32>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
}
impl UpdateFleetCapacityInputBuilder {
    /// <p>A unique identifier for the fleet to update capacity settings for. You can use either the fleet ID or ARN value.</p>
    /// This field is required.
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the fleet to update capacity settings for. You can use either the fleet ID or ARN value.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>A unique identifier for the fleet to update capacity settings for. You can use either the fleet ID or ARN value.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// <p>The number of Amazon EC2 instances you want to maintain in the specified fleet location. This value must fall between the minimum and maximum size limits. Changes in desired instance value can take up to 1 minute to be reflected when viewing the fleet's capacity settings.</p>
    pub fn desired_instances(mut self, input: i32) -> Self {
        self.desired_instances = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of Amazon EC2 instances you want to maintain in the specified fleet location. This value must fall between the minimum and maximum size limits. Changes in desired instance value can take up to 1 minute to be reflected when viewing the fleet's capacity settings.</p>
    pub fn set_desired_instances(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired_instances = input;
        self
    }
    /// <p>The number of Amazon EC2 instances you want to maintain in the specified fleet location. This value must fall between the minimum and maximum size limits. Changes in desired instance value can take up to 1 minute to be reflected when viewing the fleet's capacity settings.</p>
    pub fn get_desired_instances(&self) -> &::std::option::Option<i32> {
        &self.desired_instances
    }
    /// <p>The minimum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 0.</p>
    pub fn min_size(mut self, input: i32) -> Self {
        self.min_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 0.</p>
    pub fn set_min_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_size = input;
        self
    }
    /// <p>The minimum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 0.</p>
    pub fn get_min_size(&self) -> &::std::option::Option<i32> {
        &self.min_size
    }
    /// <p>The maximum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 1.</p>
    pub fn max_size(mut self, input: i32) -> Self {
        self.max_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 1.</p>
    pub fn set_max_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_size = input;
        self
    }
    /// <p>The maximum number of instances that are allowed in the specified fleet location. If this parameter is not set, the default is 1.</p>
    pub fn get_max_size(&self) -> &::std::option::Option<i32> {
        &self.max_size
    }
    /// <p>The name of a remote location to update fleet capacity settings for, in the form of an Amazon Web Services Region code such as <code>us-west-2</code>.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a remote location to update fleet capacity settings for, in the form of an Amazon Web Services Region code such as <code>us-west-2</code>.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The name of a remote location to update fleet capacity settings for, in the form of an Amazon Web Services Region code such as <code>us-west-2</code>.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// Consumes the builder and constructs a [`UpdateFleetCapacityInput`](crate::operation::update_fleet_capacity::UpdateFleetCapacityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_fleet_capacity::UpdateFleetCapacityInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_fleet_capacity::UpdateFleetCapacityInput {
            fleet_id: self.fleet_id,
            desired_instances: self.desired_instances,
            min_size: self.min_size,
            max_size: self.max_size,
            location: self.location,
        })
    }
}
