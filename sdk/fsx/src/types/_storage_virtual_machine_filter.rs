// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter used to restrict the results of describe calls for Amazon FSx for NetApp ONTAP storage virtual machines (SVMs). You can use multiple filters to return results that meet all applied filter requirements.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageVirtualMachineFilter {
    /// <p>The name for this filter.</p>
    pub name: ::std::option::Option<crate::types::StorageVirtualMachineFilterName>,
    /// <p>The values of the filter. These are all the values for any of the applied filters.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl StorageVirtualMachineFilter {
    /// <p>The name for this filter.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::StorageVirtualMachineFilterName> {
        self.name.as_ref()
    }
    /// <p>The values of the filter. These are all the values for any of the applied filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl StorageVirtualMachineFilter {
    /// Creates a new builder-style object to manufacture [`StorageVirtualMachineFilter`](crate::types::StorageVirtualMachineFilter).
    pub fn builder() -> crate::types::builders::StorageVirtualMachineFilterBuilder {
        crate::types::builders::StorageVirtualMachineFilterBuilder::default()
    }
}

/// A builder for [`StorageVirtualMachineFilter`](crate::types::StorageVirtualMachineFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageVirtualMachineFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::StorageVirtualMachineFilterName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl StorageVirtualMachineFilterBuilder {
    /// <p>The name for this filter.</p>
    pub fn name(mut self, input: crate::types::StorageVirtualMachineFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name for this filter.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::StorageVirtualMachineFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for this filter.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::StorageVirtualMachineFilterName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values of the filter. These are all the values for any of the applied filters.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values of the filter. These are all the values for any of the applied filters.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values of the filter. These are all the values for any of the applied filters.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`StorageVirtualMachineFilter`](crate::types::StorageVirtualMachineFilter).
    pub fn build(self) -> crate::types::StorageVirtualMachineFilter {
        crate::types::StorageVirtualMachineFilter {
            name: self.name,
            values: self.values,
        }
    }
}
