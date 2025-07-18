// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The set of properties on a table for configuring magnetic store writes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MagneticStoreWriteProperties {
    /// <p>A flag to enable magnetic store writes.</p>
    pub enable_magnetic_store_writes: bool,
    /// <p>The location to write error reports for records rejected asynchronously during magnetic store writes.</p>
    pub magnetic_store_rejected_data_location: ::std::option::Option<crate::types::MagneticStoreRejectedDataLocation>,
}
impl MagneticStoreWriteProperties {
    /// <p>A flag to enable magnetic store writes.</p>
    pub fn enable_magnetic_store_writes(&self) -> bool {
        self.enable_magnetic_store_writes
    }
    /// <p>The location to write error reports for records rejected asynchronously during magnetic store writes.</p>
    pub fn magnetic_store_rejected_data_location(&self) -> ::std::option::Option<&crate::types::MagneticStoreRejectedDataLocation> {
        self.magnetic_store_rejected_data_location.as_ref()
    }
}
impl MagneticStoreWriteProperties {
    /// Creates a new builder-style object to manufacture [`MagneticStoreWriteProperties`](crate::types::MagneticStoreWriteProperties).
    pub fn builder() -> crate::types::builders::MagneticStoreWritePropertiesBuilder {
        crate::types::builders::MagneticStoreWritePropertiesBuilder::default()
    }
}

/// A builder for [`MagneticStoreWriteProperties`](crate::types::MagneticStoreWriteProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MagneticStoreWritePropertiesBuilder {
    pub(crate) enable_magnetic_store_writes: ::std::option::Option<bool>,
    pub(crate) magnetic_store_rejected_data_location: ::std::option::Option<crate::types::MagneticStoreRejectedDataLocation>,
}
impl MagneticStoreWritePropertiesBuilder {
    /// <p>A flag to enable magnetic store writes.</p>
    /// This field is required.
    pub fn enable_magnetic_store_writes(mut self, input: bool) -> Self {
        self.enable_magnetic_store_writes = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag to enable magnetic store writes.</p>
    pub fn set_enable_magnetic_store_writes(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_magnetic_store_writes = input;
        self
    }
    /// <p>A flag to enable magnetic store writes.</p>
    pub fn get_enable_magnetic_store_writes(&self) -> &::std::option::Option<bool> {
        &self.enable_magnetic_store_writes
    }
    /// <p>The location to write error reports for records rejected asynchronously during magnetic store writes.</p>
    pub fn magnetic_store_rejected_data_location(mut self, input: crate::types::MagneticStoreRejectedDataLocation) -> Self {
        self.magnetic_store_rejected_data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location to write error reports for records rejected asynchronously during magnetic store writes.</p>
    pub fn set_magnetic_store_rejected_data_location(
        mut self,
        input: ::std::option::Option<crate::types::MagneticStoreRejectedDataLocation>,
    ) -> Self {
        self.magnetic_store_rejected_data_location = input;
        self
    }
    /// <p>The location to write error reports for records rejected asynchronously during magnetic store writes.</p>
    pub fn get_magnetic_store_rejected_data_location(&self) -> &::std::option::Option<crate::types::MagneticStoreRejectedDataLocation> {
        &self.magnetic_store_rejected_data_location
    }
    /// Consumes the builder and constructs a [`MagneticStoreWriteProperties`](crate::types::MagneticStoreWriteProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`enable_magnetic_store_writes`](crate::types::builders::MagneticStoreWritePropertiesBuilder::enable_magnetic_store_writes)
    pub fn build(self) -> ::std::result::Result<crate::types::MagneticStoreWriteProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MagneticStoreWriteProperties {
            enable_magnetic_store_writes: self.enable_magnetic_store_writes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enable_magnetic_store_writes",
                    "enable_magnetic_store_writes was not specified but it is required when building MagneticStoreWriteProperties",
                )
            })?,
            magnetic_store_rejected_data_location: self.magnetic_store_rejected_data_location,
        })
    }
}
