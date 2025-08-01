// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeviceEc2InstancesInput {
    /// <p>The ID of the managed device.</p>
    pub managed_device_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of instance IDs associated with the managed device.</p>
    pub instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDeviceEc2InstancesInput {
    /// <p>The ID of the managed device.</p>
    pub fn managed_device_id(&self) -> ::std::option::Option<&str> {
        self.managed_device_id.as_deref()
    }
    /// <p>A list of instance IDs associated with the managed device.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_ids.is_none()`.
    pub fn instance_ids(&self) -> &[::std::string::String] {
        self.instance_ids.as_deref().unwrap_or_default()
    }
}
impl DescribeDeviceEc2InstancesInput {
    /// Creates a new builder-style object to manufacture [`DescribeDeviceEc2InstancesInput`](crate::operation::describe_device_ec2_instances::DescribeDeviceEc2InstancesInput).
    pub fn builder() -> crate::operation::describe_device_ec2_instances::builders::DescribeDeviceEc2InstancesInputBuilder {
        crate::operation::describe_device_ec2_instances::builders::DescribeDeviceEc2InstancesInputBuilder::default()
    }
}

/// A builder for [`DescribeDeviceEc2InstancesInput`](crate::operation::describe_device_ec2_instances::DescribeDeviceEc2InstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDeviceEc2InstancesInputBuilder {
    pub(crate) managed_device_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDeviceEc2InstancesInputBuilder {
    /// <p>The ID of the managed device.</p>
    /// This field is required.
    pub fn managed_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the managed device.</p>
    pub fn set_managed_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_device_id = input;
        self
    }
    /// <p>The ID of the managed device.</p>
    pub fn get_managed_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_device_id
    }
    /// Appends an item to `instance_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_ids`](Self::set_instance_ids).
    ///
    /// <p>A list of instance IDs associated with the managed device.</p>
    pub fn instance_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of instance IDs associated with the managed device.</p>
    pub fn set_instance_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_ids = input;
        self
    }
    /// <p>A list of instance IDs associated with the managed device.</p>
    pub fn get_instance_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_ids
    }
    /// Consumes the builder and constructs a [`DescribeDeviceEc2InstancesInput`](crate::operation::describe_device_ec2_instances::DescribeDeviceEc2InstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_device_ec2_instances::DescribeDeviceEc2InstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_device_ec2_instances::DescribeDeviceEc2InstancesInput {
            managed_device_id: self.managed_device_id,
            instance_ids: self.instance_ids,
        })
    }
}
