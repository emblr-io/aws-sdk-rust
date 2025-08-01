// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The metadata of a single part of a file that was added to a multipart upload. A list of these parts is returned in the response to the ListReadSetUploadParts API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReadSetUploadPartListItem {
    /// <p>The number identifying the part in an upload.</p>
    pub part_number: i32,
    /// <p>The size of the the part in an upload.</p>
    pub part_size: i64,
    /// <p>The origin of the part being direct uploaded.</p>
    pub part_source: crate::types::ReadSetPartSource,
    /// <p>A unique identifier used to confirm that parts are being added to the correct upload.</p>
    pub checksum: ::std::string::String,
    /// <p>The time stamp for when a direct upload was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time stamp for the most recent update to an uploaded part.</p>
    pub last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReadSetUploadPartListItem {
    /// <p>The number identifying the part in an upload.</p>
    pub fn part_number(&self) -> i32 {
        self.part_number
    }
    /// <p>The size of the the part in an upload.</p>
    pub fn part_size(&self) -> i64 {
        self.part_size
    }
    /// <p>The origin of the part being direct uploaded.</p>
    pub fn part_source(&self) -> &crate::types::ReadSetPartSource {
        &self.part_source
    }
    /// <p>A unique identifier used to confirm that parts are being added to the correct upload.</p>
    pub fn checksum(&self) -> &str {
        use std::ops::Deref;
        self.checksum.deref()
    }
    /// <p>The time stamp for when a direct upload was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The time stamp for the most recent update to an uploaded part.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time.as_ref()
    }
}
impl ReadSetUploadPartListItem {
    /// Creates a new builder-style object to manufacture [`ReadSetUploadPartListItem`](crate::types::ReadSetUploadPartListItem).
    pub fn builder() -> crate::types::builders::ReadSetUploadPartListItemBuilder {
        crate::types::builders::ReadSetUploadPartListItemBuilder::default()
    }
}

/// A builder for [`ReadSetUploadPartListItem`](crate::types::ReadSetUploadPartListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReadSetUploadPartListItemBuilder {
    pub(crate) part_number: ::std::option::Option<i32>,
    pub(crate) part_size: ::std::option::Option<i64>,
    pub(crate) part_source: ::std::option::Option<crate::types::ReadSetPartSource>,
    pub(crate) checksum: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReadSetUploadPartListItemBuilder {
    /// <p>The number identifying the part in an upload.</p>
    /// This field is required.
    pub fn part_number(mut self, input: i32) -> Self {
        self.part_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number identifying the part in an upload.</p>
    pub fn set_part_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.part_number = input;
        self
    }
    /// <p>The number identifying the part in an upload.</p>
    pub fn get_part_number(&self) -> &::std::option::Option<i32> {
        &self.part_number
    }
    /// <p>The size of the the part in an upload.</p>
    /// This field is required.
    pub fn part_size(mut self, input: i64) -> Self {
        self.part_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the the part in an upload.</p>
    pub fn set_part_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.part_size = input;
        self
    }
    /// <p>The size of the the part in an upload.</p>
    pub fn get_part_size(&self) -> &::std::option::Option<i64> {
        &self.part_size
    }
    /// <p>The origin of the part being direct uploaded.</p>
    /// This field is required.
    pub fn part_source(mut self, input: crate::types::ReadSetPartSource) -> Self {
        self.part_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The origin of the part being direct uploaded.</p>
    pub fn set_part_source(mut self, input: ::std::option::Option<crate::types::ReadSetPartSource>) -> Self {
        self.part_source = input;
        self
    }
    /// <p>The origin of the part being direct uploaded.</p>
    pub fn get_part_source(&self) -> &::std::option::Option<crate::types::ReadSetPartSource> {
        &self.part_source
    }
    /// <p>A unique identifier used to confirm that parts are being added to the correct upload.</p>
    /// This field is required.
    pub fn checksum(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier used to confirm that parts are being added to the correct upload.</p>
    pub fn set_checksum(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum = input;
        self
    }
    /// <p>A unique identifier used to confirm that parts are being added to the correct upload.</p>
    pub fn get_checksum(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum
    }
    /// <p>The time stamp for when a direct upload was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp for when a direct upload was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time stamp for when a direct upload was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The time stamp for the most recent update to an uploaded part.</p>
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp for the most recent update to an uploaded part.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The time stamp for the most recent update to an uploaded part.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    /// Consumes the builder and constructs a [`ReadSetUploadPartListItem`](crate::types::ReadSetUploadPartListItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`part_number`](crate::types::builders::ReadSetUploadPartListItemBuilder::part_number)
    /// - [`part_size`](crate::types::builders::ReadSetUploadPartListItemBuilder::part_size)
    /// - [`part_source`](crate::types::builders::ReadSetUploadPartListItemBuilder::part_source)
    /// - [`checksum`](crate::types::builders::ReadSetUploadPartListItemBuilder::checksum)
    pub fn build(self) -> ::std::result::Result<crate::types::ReadSetUploadPartListItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ReadSetUploadPartListItem {
            part_number: self.part_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "part_number",
                    "part_number was not specified but it is required when building ReadSetUploadPartListItem",
                )
            })?,
            part_size: self.part_size.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "part_size",
                    "part_size was not specified but it is required when building ReadSetUploadPartListItem",
                )
            })?,
            part_source: self.part_source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "part_source",
                    "part_source was not specified but it is required when building ReadSetUploadPartListItem",
                )
            })?,
            checksum: self.checksum.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "checksum",
                    "checksum was not specified but it is required when building ReadSetUploadPartListItem",
                )
            })?,
            creation_time: self.creation_time,
            last_updated_time: self.last_updated_time,
        })
    }
}
