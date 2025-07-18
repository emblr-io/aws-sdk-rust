// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the FPGAs for the instance type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FpgaInfo {
    /// <p>Describes the FPGAs for the instance type.</p>
    pub fpgas: ::std::option::Option<::std::vec::Vec<crate::types::FpgaDeviceInfo>>,
    /// <p>The total memory of all FPGA accelerators for the instance type.</p>
    pub total_fpga_memory_in_mib: ::std::option::Option<i32>,
}
impl FpgaInfo {
    /// <p>Describes the FPGAs for the instance type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fpgas.is_none()`.
    pub fn fpgas(&self) -> &[crate::types::FpgaDeviceInfo] {
        self.fpgas.as_deref().unwrap_or_default()
    }
    /// <p>The total memory of all FPGA accelerators for the instance type.</p>
    pub fn total_fpga_memory_in_mib(&self) -> ::std::option::Option<i32> {
        self.total_fpga_memory_in_mib
    }
}
impl FpgaInfo {
    /// Creates a new builder-style object to manufacture [`FpgaInfo`](crate::types::FpgaInfo).
    pub fn builder() -> crate::types::builders::FpgaInfoBuilder {
        crate::types::builders::FpgaInfoBuilder::default()
    }
}

/// A builder for [`FpgaInfo`](crate::types::FpgaInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FpgaInfoBuilder {
    pub(crate) fpgas: ::std::option::Option<::std::vec::Vec<crate::types::FpgaDeviceInfo>>,
    pub(crate) total_fpga_memory_in_mib: ::std::option::Option<i32>,
}
impl FpgaInfoBuilder {
    /// Appends an item to `fpgas`.
    ///
    /// To override the contents of this collection use [`set_fpgas`](Self::set_fpgas).
    ///
    /// <p>Describes the FPGAs for the instance type.</p>
    pub fn fpgas(mut self, input: crate::types::FpgaDeviceInfo) -> Self {
        let mut v = self.fpgas.unwrap_or_default();
        v.push(input);
        self.fpgas = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the FPGAs for the instance type.</p>
    pub fn set_fpgas(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FpgaDeviceInfo>>) -> Self {
        self.fpgas = input;
        self
    }
    /// <p>Describes the FPGAs for the instance type.</p>
    pub fn get_fpgas(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FpgaDeviceInfo>> {
        &self.fpgas
    }
    /// <p>The total memory of all FPGA accelerators for the instance type.</p>
    pub fn total_fpga_memory_in_mib(mut self, input: i32) -> Self {
        self.total_fpga_memory_in_mib = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total memory of all FPGA accelerators for the instance type.</p>
    pub fn set_total_fpga_memory_in_mib(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_fpga_memory_in_mib = input;
        self
    }
    /// <p>The total memory of all FPGA accelerators for the instance type.</p>
    pub fn get_total_fpga_memory_in_mib(&self) -> &::std::option::Option<i32> {
        &self.total_fpga_memory_in_mib
    }
    /// Consumes the builder and constructs a [`FpgaInfo`](crate::types::FpgaInfo).
    pub fn build(self) -> crate::types::FpgaInfo {
        crate::types::FpgaInfo {
            fpgas: self.fpgas,
            total_fpga_memory_in_mib: self.total_fpga_memory_in_mib,
        }
    }
}
