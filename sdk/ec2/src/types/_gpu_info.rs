// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the GPU accelerators for the instance type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GpuInfo {
    /// <p>Describes the GPU accelerators for the instance type.</p>
    pub gpus: ::std::option::Option<::std::vec::Vec<crate::types::GpuDeviceInfo>>,
    /// <p>The total size of the memory for the GPU accelerators for the instance type, in MiB.</p>
    pub total_gpu_memory_in_mib: ::std::option::Option<i32>,
}
impl GpuInfo {
    /// <p>Describes the GPU accelerators for the instance type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.gpus.is_none()`.
    pub fn gpus(&self) -> &[crate::types::GpuDeviceInfo] {
        self.gpus.as_deref().unwrap_or_default()
    }
    /// <p>The total size of the memory for the GPU accelerators for the instance type, in MiB.</p>
    pub fn total_gpu_memory_in_mib(&self) -> ::std::option::Option<i32> {
        self.total_gpu_memory_in_mib
    }
}
impl GpuInfo {
    /// Creates a new builder-style object to manufacture [`GpuInfo`](crate::types::GpuInfo).
    pub fn builder() -> crate::types::builders::GpuInfoBuilder {
        crate::types::builders::GpuInfoBuilder::default()
    }
}

/// A builder for [`GpuInfo`](crate::types::GpuInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GpuInfoBuilder {
    pub(crate) gpus: ::std::option::Option<::std::vec::Vec<crate::types::GpuDeviceInfo>>,
    pub(crate) total_gpu_memory_in_mib: ::std::option::Option<i32>,
}
impl GpuInfoBuilder {
    /// Appends an item to `gpus`.
    ///
    /// To override the contents of this collection use [`set_gpus`](Self::set_gpus).
    ///
    /// <p>Describes the GPU accelerators for the instance type.</p>
    pub fn gpus(mut self, input: crate::types::GpuDeviceInfo) -> Self {
        let mut v = self.gpus.unwrap_or_default();
        v.push(input);
        self.gpus = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the GPU accelerators for the instance type.</p>
    pub fn set_gpus(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GpuDeviceInfo>>) -> Self {
        self.gpus = input;
        self
    }
    /// <p>Describes the GPU accelerators for the instance type.</p>
    pub fn get_gpus(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GpuDeviceInfo>> {
        &self.gpus
    }
    /// <p>The total size of the memory for the GPU accelerators for the instance type, in MiB.</p>
    pub fn total_gpu_memory_in_mib(mut self, input: i32) -> Self {
        self.total_gpu_memory_in_mib = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total size of the memory for the GPU accelerators for the instance type, in MiB.</p>
    pub fn set_total_gpu_memory_in_mib(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_gpu_memory_in_mib = input;
        self
    }
    /// <p>The total size of the memory for the GPU accelerators for the instance type, in MiB.</p>
    pub fn get_total_gpu_memory_in_mib(&self) -> &::std::option::Option<i32> {
        &self.total_gpu_memory_in_mib
    }
    /// Consumes the builder and constructs a [`GpuInfo`](crate::types::GpuInfo).
    pub fn build(self) -> crate::types::GpuInfo {
        crate::types::GpuInfo {
            gpus: self.gpus,
            total_gpu_memory_in_mib: self.total_gpu_memory_in_mib,
        }
    }
}
