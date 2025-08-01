// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataSetDetailsOutput {
    /// <p>The name of the data set.</p>
    pub data_set_name: ::std::string::String,
    /// <p>The type of data set. The only supported value is VSAM.</p>
    pub data_set_org: ::std::option::Option<crate::types::DatasetDetailOrgAttributes>,
    /// <p>The length of records in the data set.</p>
    pub record_length: ::std::option::Option<i32>,
    /// <p>The location where the data set is stored.</p>
    pub location: ::std::option::Option<::std::string::String>,
    /// <p>The size of the block on disk.</p>
    pub blocksize: ::std::option::Option<i32>,
    /// <p>The timestamp when the data set was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last time the data set was updated.</p>
    pub last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last time the data set was referenced.</p>
    pub last_referenced_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>File size of the dataset.</p>
    pub file_size: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetDataSetDetailsOutput {
    /// <p>The name of the data set.</p>
    pub fn data_set_name(&self) -> &str {
        use std::ops::Deref;
        self.data_set_name.deref()
    }
    /// <p>The type of data set. The only supported value is VSAM.</p>
    pub fn data_set_org(&self) -> ::std::option::Option<&crate::types::DatasetDetailOrgAttributes> {
        self.data_set_org.as_ref()
    }
    /// <p>The length of records in the data set.</p>
    pub fn record_length(&self) -> ::std::option::Option<i32> {
        self.record_length
    }
    /// <p>The location where the data set is stored.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
    /// <p>The size of the block on disk.</p>
    pub fn blocksize(&self) -> ::std::option::Option<i32> {
        self.blocksize
    }
    /// <p>The timestamp when the data set was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The last time the data set was updated.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time.as_ref()
    }
    /// <p>The last time the data set was referenced.</p>
    pub fn last_referenced_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_referenced_time.as_ref()
    }
    /// <p>File size of the dataset.</p>
    pub fn file_size(&self) -> ::std::option::Option<i64> {
        self.file_size
    }
}
impl ::aws_types::request_id::RequestId for GetDataSetDetailsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDataSetDetailsOutput {
    /// Creates a new builder-style object to manufacture [`GetDataSetDetailsOutput`](crate::operation::get_data_set_details::GetDataSetDetailsOutput).
    pub fn builder() -> crate::operation::get_data_set_details::builders::GetDataSetDetailsOutputBuilder {
        crate::operation::get_data_set_details::builders::GetDataSetDetailsOutputBuilder::default()
    }
}

/// A builder for [`GetDataSetDetailsOutput`](crate::operation::get_data_set_details::GetDataSetDetailsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataSetDetailsOutputBuilder {
    pub(crate) data_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_set_org: ::std::option::Option<crate::types::DatasetDetailOrgAttributes>,
    pub(crate) record_length: ::std::option::Option<i32>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) blocksize: ::std::option::Option<i32>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_referenced_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) file_size: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetDataSetDetailsOutputBuilder {
    /// <p>The name of the data set.</p>
    /// This field is required.
    pub fn data_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data set.</p>
    pub fn set_data_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_name = input;
        self
    }
    /// <p>The name of the data set.</p>
    pub fn get_data_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_name
    }
    /// <p>The type of data set. The only supported value is VSAM.</p>
    pub fn data_set_org(mut self, input: crate::types::DatasetDetailOrgAttributes) -> Self {
        self.data_set_org = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of data set. The only supported value is VSAM.</p>
    pub fn set_data_set_org(mut self, input: ::std::option::Option<crate::types::DatasetDetailOrgAttributes>) -> Self {
        self.data_set_org = input;
        self
    }
    /// <p>The type of data set. The only supported value is VSAM.</p>
    pub fn get_data_set_org(&self) -> &::std::option::Option<crate::types::DatasetDetailOrgAttributes> {
        &self.data_set_org
    }
    /// <p>The length of records in the data set.</p>
    pub fn record_length(mut self, input: i32) -> Self {
        self.record_length = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of records in the data set.</p>
    pub fn set_record_length(mut self, input: ::std::option::Option<i32>) -> Self {
        self.record_length = input;
        self
    }
    /// <p>The length of records in the data set.</p>
    pub fn get_record_length(&self) -> &::std::option::Option<i32> {
        &self.record_length
    }
    /// <p>The location where the data set is stored.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location where the data set is stored.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The location where the data set is stored.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// <p>The size of the block on disk.</p>
    pub fn blocksize(mut self, input: i32) -> Self {
        self.blocksize = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the block on disk.</p>
    pub fn set_blocksize(mut self, input: ::std::option::Option<i32>) -> Self {
        self.blocksize = input;
        self
    }
    /// <p>The size of the block on disk.</p>
    pub fn get_blocksize(&self) -> &::std::option::Option<i32> {
        &self.blocksize
    }
    /// <p>The timestamp when the data set was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the data set was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The timestamp when the data set was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The last time the data set was updated.</p>
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the data set was updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The last time the data set was updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    /// <p>The last time the data set was referenced.</p>
    pub fn last_referenced_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_referenced_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the data set was referenced.</p>
    pub fn set_last_referenced_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_referenced_time = input;
        self
    }
    /// <p>The last time the data set was referenced.</p>
    pub fn get_last_referenced_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_referenced_time
    }
    /// <p>File size of the dataset.</p>
    pub fn file_size(mut self, input: i64) -> Self {
        self.file_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>File size of the dataset.</p>
    pub fn set_file_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.file_size = input;
        self
    }
    /// <p>File size of the dataset.</p>
    pub fn get_file_size(&self) -> &::std::option::Option<i64> {
        &self.file_size
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDataSetDetailsOutput`](crate::operation::get_data_set_details::GetDataSetDetailsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_set_name`](crate::operation::get_data_set_details::builders::GetDataSetDetailsOutputBuilder::data_set_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_data_set_details::GetDataSetDetailsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_data_set_details::GetDataSetDetailsOutput {
            data_set_name: self.data_set_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_name",
                    "data_set_name was not specified but it is required when building GetDataSetDetailsOutput",
                )
            })?,
            data_set_org: self.data_set_org,
            record_length: self.record_length,
            location: self.location,
            blocksize: self.blocksize,
            creation_time: self.creation_time,
            last_updated_time: self.last_updated_time,
            last_referenced_time: self.last_referenced_time,
            file_size: self.file_size,
            _request_id: self._request_id,
        })
    }
}
