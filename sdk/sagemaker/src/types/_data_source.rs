// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the location of the channel data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSource {
    /// <p>The S3 location of the data source that is associated with a channel.</p>
    pub s3_data_source: ::std::option::Option<crate::types::S3DataSource>,
    /// <p>The file system that is associated with a channel.</p>
    pub file_system_data_source: ::std::option::Option<crate::types::FileSystemDataSource>,
}
impl DataSource {
    /// <p>The S3 location of the data source that is associated with a channel.</p>
    pub fn s3_data_source(&self) -> ::std::option::Option<&crate::types::S3DataSource> {
        self.s3_data_source.as_ref()
    }
    /// <p>The file system that is associated with a channel.</p>
    pub fn file_system_data_source(&self) -> ::std::option::Option<&crate::types::FileSystemDataSource> {
        self.file_system_data_source.as_ref()
    }
}
impl DataSource {
    /// Creates a new builder-style object to manufacture [`DataSource`](crate::types::DataSource).
    pub fn builder() -> crate::types::builders::DataSourceBuilder {
        crate::types::builders::DataSourceBuilder::default()
    }
}

/// A builder for [`DataSource`](crate::types::DataSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSourceBuilder {
    pub(crate) s3_data_source: ::std::option::Option<crate::types::S3DataSource>,
    pub(crate) file_system_data_source: ::std::option::Option<crate::types::FileSystemDataSource>,
}
impl DataSourceBuilder {
    /// <p>The S3 location of the data source that is associated with a channel.</p>
    pub fn s3_data_source(mut self, input: crate::types::S3DataSource) -> Self {
        self.s3_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The S3 location of the data source that is associated with a channel.</p>
    pub fn set_s3_data_source(mut self, input: ::std::option::Option<crate::types::S3DataSource>) -> Self {
        self.s3_data_source = input;
        self
    }
    /// <p>The S3 location of the data source that is associated with a channel.</p>
    pub fn get_s3_data_source(&self) -> &::std::option::Option<crate::types::S3DataSource> {
        &self.s3_data_source
    }
    /// <p>The file system that is associated with a channel.</p>
    pub fn file_system_data_source(mut self, input: crate::types::FileSystemDataSource) -> Self {
        self.file_system_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file system that is associated with a channel.</p>
    pub fn set_file_system_data_source(mut self, input: ::std::option::Option<crate::types::FileSystemDataSource>) -> Self {
        self.file_system_data_source = input;
        self
    }
    /// <p>The file system that is associated with a channel.</p>
    pub fn get_file_system_data_source(&self) -> &::std::option::Option<crate::types::FileSystemDataSource> {
        &self.file_system_data_source
    }
    /// Consumes the builder and constructs a [`DataSource`](crate::types::DataSource).
    pub fn build(self) -> crate::types::DataSource {
        crate::types::DataSource {
            s3_data_source: self.s3_data_source,
            file_system_data_source: self.file_system_data_source,
        }
    }
}
