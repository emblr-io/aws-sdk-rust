// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the CPU options for an Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-optimize-cpu.html">Optimize CPU options</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2LaunchTemplateDataCpuOptionsDetails {
    /// <p>The number of CPU cores for the instance.</p>
    pub core_count: ::std::option::Option<i32>,
    /// <p>The number of threads per CPU core. A value of <code>1</code> disables multithreading for the instance, The default value is <code>2</code>.</p>
    pub threads_per_core: ::std::option::Option<i32>,
}
impl AwsEc2LaunchTemplateDataCpuOptionsDetails {
    /// <p>The number of CPU cores for the instance.</p>
    pub fn core_count(&self) -> ::std::option::Option<i32> {
        self.core_count
    }
    /// <p>The number of threads per CPU core. A value of <code>1</code> disables multithreading for the instance, The default value is <code>2</code>.</p>
    pub fn threads_per_core(&self) -> ::std::option::Option<i32> {
        self.threads_per_core
    }
}
impl AwsEc2LaunchTemplateDataCpuOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2LaunchTemplateDataCpuOptionsDetails`](crate::types::AwsEc2LaunchTemplateDataCpuOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsEc2LaunchTemplateDataCpuOptionsDetailsBuilder {
        crate::types::builders::AwsEc2LaunchTemplateDataCpuOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2LaunchTemplateDataCpuOptionsDetails`](crate::types::AwsEc2LaunchTemplateDataCpuOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2LaunchTemplateDataCpuOptionsDetailsBuilder {
    pub(crate) core_count: ::std::option::Option<i32>,
    pub(crate) threads_per_core: ::std::option::Option<i32>,
}
impl AwsEc2LaunchTemplateDataCpuOptionsDetailsBuilder {
    /// <p>The number of CPU cores for the instance.</p>
    pub fn core_count(mut self, input: i32) -> Self {
        self.core_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of CPU cores for the instance.</p>
    pub fn set_core_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.core_count = input;
        self
    }
    /// <p>The number of CPU cores for the instance.</p>
    pub fn get_core_count(&self) -> &::std::option::Option<i32> {
        &self.core_count
    }
    /// <p>The number of threads per CPU core. A value of <code>1</code> disables multithreading for the instance, The default value is <code>2</code>.</p>
    pub fn threads_per_core(mut self, input: i32) -> Self {
        self.threads_per_core = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of threads per CPU core. A value of <code>1</code> disables multithreading for the instance, The default value is <code>2</code>.</p>
    pub fn set_threads_per_core(mut self, input: ::std::option::Option<i32>) -> Self {
        self.threads_per_core = input;
        self
    }
    /// <p>The number of threads per CPU core. A value of <code>1</code> disables multithreading for the instance, The default value is <code>2</code>.</p>
    pub fn get_threads_per_core(&self) -> &::std::option::Option<i32> {
        &self.threads_per_core
    }
    /// Consumes the builder and constructs a [`AwsEc2LaunchTemplateDataCpuOptionsDetails`](crate::types::AwsEc2LaunchTemplateDataCpuOptionsDetails).
    pub fn build(self) -> crate::types::AwsEc2LaunchTemplateDataCpuOptionsDetails {
        crate::types::AwsEc2LaunchTemplateDataCpuOptionsDetails {
            core_count: self.core_count,
            threads_per_core: self.threads_per_core,
        }
    }
}
