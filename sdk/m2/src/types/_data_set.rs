// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a data set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSet {
    /// <p>The storage type of the data set: database or file system. For Micro Focus, database corresponds to datastore and file system corresponds to EFS/FSX. For Blu Age, there is no support of file system and database corresponds to Blusam.</p>
    pub storage_type: ::std::option::Option<::std::string::String>,
    /// <p>The logical identifier for a specific data set (in mainframe format).</p>
    pub dataset_name: ::std::string::String,
    /// <p>The type of dataset. The only supported value is VSAM.</p>
    pub dataset_org: ::std::option::Option<crate::types::DatasetOrgAttributes>,
    /// <p>The relative location of the data set in the database or file system.</p>
    pub relative_path: ::std::option::Option<::std::string::String>,
    /// <p>The length of a record.</p>
    pub record_length: ::std::option::Option<crate::types::RecordLength>,
}
impl DataSet {
    /// <p>The storage type of the data set: database or file system. For Micro Focus, database corresponds to datastore and file system corresponds to EFS/FSX. For Blu Age, there is no support of file system and database corresponds to Blusam.</p>
    pub fn storage_type(&self) -> ::std::option::Option<&str> {
        self.storage_type.as_deref()
    }
    /// <p>The logical identifier for a specific data set (in mainframe format).</p>
    pub fn dataset_name(&self) -> &str {
        use std::ops::Deref;
        self.dataset_name.deref()
    }
    /// <p>The type of dataset. The only supported value is VSAM.</p>
    pub fn dataset_org(&self) -> ::std::option::Option<&crate::types::DatasetOrgAttributes> {
        self.dataset_org.as_ref()
    }
    /// <p>The relative location of the data set in the database or file system.</p>
    pub fn relative_path(&self) -> ::std::option::Option<&str> {
        self.relative_path.as_deref()
    }
    /// <p>The length of a record.</p>
    pub fn record_length(&self) -> ::std::option::Option<&crate::types::RecordLength> {
        self.record_length.as_ref()
    }
}
impl DataSet {
    /// Creates a new builder-style object to manufacture [`DataSet`](crate::types::DataSet).
    pub fn builder() -> crate::types::builders::DataSetBuilder {
        crate::types::builders::DataSetBuilder::default()
    }
}

/// A builder for [`DataSet`](crate::types::DataSet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSetBuilder {
    pub(crate) storage_type: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_name: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_org: ::std::option::Option<crate::types::DatasetOrgAttributes>,
    pub(crate) relative_path: ::std::option::Option<::std::string::String>,
    pub(crate) record_length: ::std::option::Option<crate::types::RecordLength>,
}
impl DataSetBuilder {
    /// <p>The storage type of the data set: database or file system. For Micro Focus, database corresponds to datastore and file system corresponds to EFS/FSX. For Blu Age, there is no support of file system and database corresponds to Blusam.</p>
    pub fn storage_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.storage_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The storage type of the data set: database or file system. For Micro Focus, database corresponds to datastore and file system corresponds to EFS/FSX. For Blu Age, there is no support of file system and database corresponds to Blusam.</p>
    pub fn set_storage_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.storage_type = input;
        self
    }
    /// <p>The storage type of the data set: database or file system. For Micro Focus, database corresponds to datastore and file system corresponds to EFS/FSX. For Blu Age, there is no support of file system and database corresponds to Blusam.</p>
    pub fn get_storage_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.storage_type
    }
    /// <p>The logical identifier for a specific data set (in mainframe format).</p>
    /// This field is required.
    pub fn dataset_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The logical identifier for a specific data set (in mainframe format).</p>
    pub fn set_dataset_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_name = input;
        self
    }
    /// <p>The logical identifier for a specific data set (in mainframe format).</p>
    pub fn get_dataset_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_name
    }
    /// <p>The type of dataset. The only supported value is VSAM.</p>
    /// This field is required.
    pub fn dataset_org(mut self, input: crate::types::DatasetOrgAttributes) -> Self {
        self.dataset_org = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of dataset. The only supported value is VSAM.</p>
    pub fn set_dataset_org(mut self, input: ::std::option::Option<crate::types::DatasetOrgAttributes>) -> Self {
        self.dataset_org = input;
        self
    }
    /// <p>The type of dataset. The only supported value is VSAM.</p>
    pub fn get_dataset_org(&self) -> &::std::option::Option<crate::types::DatasetOrgAttributes> {
        &self.dataset_org
    }
    /// <p>The relative location of the data set in the database or file system.</p>
    pub fn relative_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.relative_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The relative location of the data set in the database or file system.</p>
    pub fn set_relative_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.relative_path = input;
        self
    }
    /// <p>The relative location of the data set in the database or file system.</p>
    pub fn get_relative_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.relative_path
    }
    /// <p>The length of a record.</p>
    /// This field is required.
    pub fn record_length(mut self, input: crate::types::RecordLength) -> Self {
        self.record_length = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of a record.</p>
    pub fn set_record_length(mut self, input: ::std::option::Option<crate::types::RecordLength>) -> Self {
        self.record_length = input;
        self
    }
    /// <p>The length of a record.</p>
    pub fn get_record_length(&self) -> &::std::option::Option<crate::types::RecordLength> {
        &self.record_length
    }
    /// Consumes the builder and constructs a [`DataSet`](crate::types::DataSet).
    /// This method will fail if any of the following fields are not set:
    /// - [`dataset_name`](crate::types::builders::DataSetBuilder::dataset_name)
    pub fn build(self) -> ::std::result::Result<crate::types::DataSet, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataSet {
            storage_type: self.storage_type,
            dataset_name: self.dataset_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dataset_name",
                    "dataset_name was not specified but it is required when building DataSet",
                )
            })?,
            dataset_org: self.dataset_org,
            relative_path: self.relative_path,
            record_length: self.record_length,
        })
    }
}
