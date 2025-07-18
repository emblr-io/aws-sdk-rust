// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDataSourceFromS3Input {
    /// <p>A user-supplied identifier that uniquely identifies the <code>DataSource</code>.</p>
    pub data_source_id: ::std::option::Option<::std::string::String>,
    /// <p>A user-supplied name or description of the <code>DataSource</code>.</p>
    pub data_source_name: ::std::option::Option<::std::string::String>,
    /// <p>The data specification of a <code>DataSource</code>:</p>
    /// <ul>
    /// <li>
    /// <p>DataLocationS3 - The Amazon S3 location of the observation data.</p></li>
    /// <li>
    /// <p>DataSchemaLocationS3 - The Amazon S3 location of the <code>DataSchema</code>.</p></li>
    /// <li>
    /// <p>DataSchema - A JSON string representing the schema. This is not required if <code>DataSchemaUri</code> is specified.</p></li>
    /// <li>
    /// <p>DataRearrangement - A JSON string that represents the splitting and rearrangement requirements for the <code>Datasource</code>.</p>
    /// <p>Sample - <code> "{\"splitting\":{\"percentBegin\":10,\"percentEnd\":60}}"</code></p></li>
    /// </ul>
    pub data_spec: ::std::option::Option<crate::types::S3DataSpec>,
    /// <p>The compute statistics for a <code>DataSource</code>. The statistics are generated from the observation data referenced by a <code>DataSource</code>. Amazon ML uses the statistics internally during <code>MLModel</code> training. This parameter must be set to <code>true</code> if the <code></code>DataSource<code></code> needs to be used for <code>MLModel</code> training.</p>
    pub compute_statistics: ::std::option::Option<bool>,
}
impl CreateDataSourceFromS3Input {
    /// <p>A user-supplied identifier that uniquely identifies the <code>DataSource</code>.</p>
    pub fn data_source_id(&self) -> ::std::option::Option<&str> {
        self.data_source_id.as_deref()
    }
    /// <p>A user-supplied name or description of the <code>DataSource</code>.</p>
    pub fn data_source_name(&self) -> ::std::option::Option<&str> {
        self.data_source_name.as_deref()
    }
    /// <p>The data specification of a <code>DataSource</code>:</p>
    /// <ul>
    /// <li>
    /// <p>DataLocationS3 - The Amazon S3 location of the observation data.</p></li>
    /// <li>
    /// <p>DataSchemaLocationS3 - The Amazon S3 location of the <code>DataSchema</code>.</p></li>
    /// <li>
    /// <p>DataSchema - A JSON string representing the schema. This is not required if <code>DataSchemaUri</code> is specified.</p></li>
    /// <li>
    /// <p>DataRearrangement - A JSON string that represents the splitting and rearrangement requirements for the <code>Datasource</code>.</p>
    /// <p>Sample - <code> "{\"splitting\":{\"percentBegin\":10,\"percentEnd\":60}}"</code></p></li>
    /// </ul>
    pub fn data_spec(&self) -> ::std::option::Option<&crate::types::S3DataSpec> {
        self.data_spec.as_ref()
    }
    /// <p>The compute statistics for a <code>DataSource</code>. The statistics are generated from the observation data referenced by a <code>DataSource</code>. Amazon ML uses the statistics internally during <code>MLModel</code> training. This parameter must be set to <code>true</code> if the <code></code>DataSource<code></code> needs to be used for <code>MLModel</code> training.</p>
    pub fn compute_statistics(&self) -> ::std::option::Option<bool> {
        self.compute_statistics
    }
}
impl CreateDataSourceFromS3Input {
    /// Creates a new builder-style object to manufacture [`CreateDataSourceFromS3Input`](crate::operation::create_data_source_from_s3::CreateDataSourceFromS3Input).
    pub fn builder() -> crate::operation::create_data_source_from_s3::builders::CreateDataSourceFromS3InputBuilder {
        crate::operation::create_data_source_from_s3::builders::CreateDataSourceFromS3InputBuilder::default()
    }
}

/// A builder for [`CreateDataSourceFromS3Input`](crate::operation::create_data_source_from_s3::CreateDataSourceFromS3Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDataSourceFromS3InputBuilder {
    pub(crate) data_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_source_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_spec: ::std::option::Option<crate::types::S3DataSpec>,
    pub(crate) compute_statistics: ::std::option::Option<bool>,
}
impl CreateDataSourceFromS3InputBuilder {
    /// <p>A user-supplied identifier that uniquely identifies the <code>DataSource</code>.</p>
    /// This field is required.
    pub fn data_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-supplied identifier that uniquely identifies the <code>DataSource</code>.</p>
    pub fn set_data_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_id = input;
        self
    }
    /// <p>A user-supplied identifier that uniquely identifies the <code>DataSource</code>.</p>
    pub fn get_data_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_id
    }
    /// <p>A user-supplied name or description of the <code>DataSource</code>.</p>
    pub fn data_source_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-supplied name or description of the <code>DataSource</code>.</p>
    pub fn set_data_source_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_name = input;
        self
    }
    /// <p>A user-supplied name or description of the <code>DataSource</code>.</p>
    pub fn get_data_source_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_name
    }
    /// <p>The data specification of a <code>DataSource</code>:</p>
    /// <ul>
    /// <li>
    /// <p>DataLocationS3 - The Amazon S3 location of the observation data.</p></li>
    /// <li>
    /// <p>DataSchemaLocationS3 - The Amazon S3 location of the <code>DataSchema</code>.</p></li>
    /// <li>
    /// <p>DataSchema - A JSON string representing the schema. This is not required if <code>DataSchemaUri</code> is specified.</p></li>
    /// <li>
    /// <p>DataRearrangement - A JSON string that represents the splitting and rearrangement requirements for the <code>Datasource</code>.</p>
    /// <p>Sample - <code> "{\"splitting\":{\"percentBegin\":10,\"percentEnd\":60}}"</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn data_spec(mut self, input: crate::types::S3DataSpec) -> Self {
        self.data_spec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data specification of a <code>DataSource</code>:</p>
    /// <ul>
    /// <li>
    /// <p>DataLocationS3 - The Amazon S3 location of the observation data.</p></li>
    /// <li>
    /// <p>DataSchemaLocationS3 - The Amazon S3 location of the <code>DataSchema</code>.</p></li>
    /// <li>
    /// <p>DataSchema - A JSON string representing the schema. This is not required if <code>DataSchemaUri</code> is specified.</p></li>
    /// <li>
    /// <p>DataRearrangement - A JSON string that represents the splitting and rearrangement requirements for the <code>Datasource</code>.</p>
    /// <p>Sample - <code> "{\"splitting\":{\"percentBegin\":10,\"percentEnd\":60}}"</code></p></li>
    /// </ul>
    pub fn set_data_spec(mut self, input: ::std::option::Option<crate::types::S3DataSpec>) -> Self {
        self.data_spec = input;
        self
    }
    /// <p>The data specification of a <code>DataSource</code>:</p>
    /// <ul>
    /// <li>
    /// <p>DataLocationS3 - The Amazon S3 location of the observation data.</p></li>
    /// <li>
    /// <p>DataSchemaLocationS3 - The Amazon S3 location of the <code>DataSchema</code>.</p></li>
    /// <li>
    /// <p>DataSchema - A JSON string representing the schema. This is not required if <code>DataSchemaUri</code> is specified.</p></li>
    /// <li>
    /// <p>DataRearrangement - A JSON string that represents the splitting and rearrangement requirements for the <code>Datasource</code>.</p>
    /// <p>Sample - <code> "{\"splitting\":{\"percentBegin\":10,\"percentEnd\":60}}"</code></p></li>
    /// </ul>
    pub fn get_data_spec(&self) -> &::std::option::Option<crate::types::S3DataSpec> {
        &self.data_spec
    }
    /// <p>The compute statistics for a <code>DataSource</code>. The statistics are generated from the observation data referenced by a <code>DataSource</code>. Amazon ML uses the statistics internally during <code>MLModel</code> training. This parameter must be set to <code>true</code> if the <code></code>DataSource<code></code> needs to be used for <code>MLModel</code> training.</p>
    pub fn compute_statistics(mut self, input: bool) -> Self {
        self.compute_statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute statistics for a <code>DataSource</code>. The statistics are generated from the observation data referenced by a <code>DataSource</code>. Amazon ML uses the statistics internally during <code>MLModel</code> training. This parameter must be set to <code>true</code> if the <code></code>DataSource<code></code> needs to be used for <code>MLModel</code> training.</p>
    pub fn set_compute_statistics(mut self, input: ::std::option::Option<bool>) -> Self {
        self.compute_statistics = input;
        self
    }
    /// <p>The compute statistics for a <code>DataSource</code>. The statistics are generated from the observation data referenced by a <code>DataSource</code>. Amazon ML uses the statistics internally during <code>MLModel</code> training. This parameter must be set to <code>true</code> if the <code></code>DataSource<code></code> needs to be used for <code>MLModel</code> training.</p>
    pub fn get_compute_statistics(&self) -> &::std::option::Option<bool> {
        &self.compute_statistics
    }
    /// Consumes the builder and constructs a [`CreateDataSourceFromS3Input`](crate::operation::create_data_source_from_s3::CreateDataSourceFromS3Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_data_source_from_s3::CreateDataSourceFromS3Input,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_data_source_from_s3::CreateDataSourceFromS3Input {
            data_source_id: self.data_source_id,
            data_source_name: self.data_source_name,
            data_spec: self.data_spec,
            compute_statistics: self.compute_statistics,
        })
    }
}
