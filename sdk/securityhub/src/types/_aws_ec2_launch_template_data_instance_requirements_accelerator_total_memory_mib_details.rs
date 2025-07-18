// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The minimum and maximum amount of memory, in MiB, for the accelerators on an Amazon EC2 instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails {
    /// <p>The maximum amount of memory, in MiB. If this parameter isn't specified, there's no maximum limit.</p>
    pub max: ::std::option::Option<i32>,
    /// <p>The minimum amount of memory, in MiB. If <code>0</code> is specified, there's no maximum limit.</p>
    pub min: ::std::option::Option<i32>,
}
impl AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails {
    /// <p>The maximum amount of memory, in MiB. If this parameter isn't specified, there's no maximum limit.</p>
    pub fn max(&self) -> ::std::option::Option<i32> {
        self.max
    }
    /// <p>The minimum amount of memory, in MiB. If <code>0</code> is specified, there's no maximum limit.</p>
    pub fn min(&self) -> ::std::option::Option<i32> {
        self.min
    }
}
impl AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails`](crate::types::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails).
    pub fn builder() -> crate::types::builders::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetailsBuilder {
        crate::types::builders::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails`](crate::types::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetailsBuilder {
    pub(crate) max: ::std::option::Option<i32>,
    pub(crate) min: ::std::option::Option<i32>,
}
impl AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetailsBuilder {
    /// <p>The maximum amount of memory, in MiB. If this parameter isn't specified, there's no maximum limit.</p>
    pub fn max(mut self, input: i32) -> Self {
        self.max = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of memory, in MiB. If this parameter isn't specified, there's no maximum limit.</p>
    pub fn set_max(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max = input;
        self
    }
    /// <p>The maximum amount of memory, in MiB. If this parameter isn't specified, there's no maximum limit.</p>
    pub fn get_max(&self) -> &::std::option::Option<i32> {
        &self.max
    }
    /// <p>The minimum amount of memory, in MiB. If <code>0</code> is specified, there's no maximum limit.</p>
    pub fn min(mut self, input: i32) -> Self {
        self.min = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum amount of memory, in MiB. If <code>0</code> is specified, there's no maximum limit.</p>
    pub fn set_min(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min = input;
        self
    }
    /// <p>The minimum amount of memory, in MiB. If <code>0</code> is specified, there's no maximum limit.</p>
    pub fn get_min(&self) -> &::std::option::Option<i32> {
        &self.min
    }
    /// Consumes the builder and constructs a [`AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails`](crate::types::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails).
    pub fn build(self) -> crate::types::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails {
        crate::types::AwsEc2LaunchTemplateDataInstanceRequirementsAcceleratorTotalMemoryMiBDetails {
            max: self.max,
            min: self.min,
        }
    }
}
