// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a storage location for images extracted from multimodal documents in your data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SupplementalDataStorageLocation {
    /// <p>Specifies the storage service used for this location.</p>
    pub r#type: crate::types::SupplementalDataStorageLocationType,
    /// <p>Contains information about the Amazon S3 location for the extracted images.</p>
    pub s3_location: ::std::option::Option<crate::types::S3Location>,
}
impl SupplementalDataStorageLocation {
    /// <p>Specifies the storage service used for this location.</p>
    pub fn r#type(&self) -> &crate::types::SupplementalDataStorageLocationType {
        &self.r#type
    }
    /// <p>Contains information about the Amazon S3 location for the extracted images.</p>
    pub fn s3_location(&self) -> ::std::option::Option<&crate::types::S3Location> {
        self.s3_location.as_ref()
    }
}
impl SupplementalDataStorageLocation {
    /// Creates a new builder-style object to manufacture [`SupplementalDataStorageLocation`](crate::types::SupplementalDataStorageLocation).
    pub fn builder() -> crate::types::builders::SupplementalDataStorageLocationBuilder {
        crate::types::builders::SupplementalDataStorageLocationBuilder::default()
    }
}

/// A builder for [`SupplementalDataStorageLocation`](crate::types::SupplementalDataStorageLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SupplementalDataStorageLocationBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::SupplementalDataStorageLocationType>,
    pub(crate) s3_location: ::std::option::Option<crate::types::S3Location>,
}
impl SupplementalDataStorageLocationBuilder {
    /// <p>Specifies the storage service used for this location.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::SupplementalDataStorageLocationType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the storage service used for this location.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::SupplementalDataStorageLocationType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the storage service used for this location.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::SupplementalDataStorageLocationType> {
        &self.r#type
    }
    /// <p>Contains information about the Amazon S3 location for the extracted images.</p>
    pub fn s3_location(mut self, input: crate::types::S3Location) -> Self {
        self.s3_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the Amazon S3 location for the extracted images.</p>
    pub fn set_s3_location(mut self, input: ::std::option::Option<crate::types::S3Location>) -> Self {
        self.s3_location = input;
        self
    }
    /// <p>Contains information about the Amazon S3 location for the extracted images.</p>
    pub fn get_s3_location(&self) -> &::std::option::Option<crate::types::S3Location> {
        &self.s3_location
    }
    /// Consumes the builder and constructs a [`SupplementalDataStorageLocation`](crate::types::SupplementalDataStorageLocation).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::SupplementalDataStorageLocationBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::SupplementalDataStorageLocation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SupplementalDataStorageLocation {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building SupplementalDataStorageLocation",
                )
            })?,
            s3_location: self.s3_location,
        })
    }
}
