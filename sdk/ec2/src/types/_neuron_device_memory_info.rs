// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the memory available to the neuron accelerator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NeuronDeviceMemoryInfo {
    /// <p>The size of the memory available to the neuron accelerator, in MiB.</p>
    pub size_in_mib: ::std::option::Option<i32>,
}
impl NeuronDeviceMemoryInfo {
    /// <p>The size of the memory available to the neuron accelerator, in MiB.</p>
    pub fn size_in_mib(&self) -> ::std::option::Option<i32> {
        self.size_in_mib
    }
}
impl NeuronDeviceMemoryInfo {
    /// Creates a new builder-style object to manufacture [`NeuronDeviceMemoryInfo`](crate::types::NeuronDeviceMemoryInfo).
    pub fn builder() -> crate::types::builders::NeuronDeviceMemoryInfoBuilder {
        crate::types::builders::NeuronDeviceMemoryInfoBuilder::default()
    }
}

/// A builder for [`NeuronDeviceMemoryInfo`](crate::types::NeuronDeviceMemoryInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NeuronDeviceMemoryInfoBuilder {
    pub(crate) size_in_mib: ::std::option::Option<i32>,
}
impl NeuronDeviceMemoryInfoBuilder {
    /// <p>The size of the memory available to the neuron accelerator, in MiB.</p>
    pub fn size_in_mib(mut self, input: i32) -> Self {
        self.size_in_mib = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the memory available to the neuron accelerator, in MiB.</p>
    pub fn set_size_in_mib(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_mib = input;
        self
    }
    /// <p>The size of the memory available to the neuron accelerator, in MiB.</p>
    pub fn get_size_in_mib(&self) -> &::std::option::Option<i32> {
        &self.size_in_mib
    }
    /// Consumes the builder and constructs a [`NeuronDeviceMemoryInfo`](crate::types::NeuronDeviceMemoryInfo).
    pub fn build(self) -> crate::types::NeuronDeviceMemoryInfo {
        crate::types::NeuronDeviceMemoryInfo {
            size_in_mib: self.size_in_mib,
        }
    }
}
