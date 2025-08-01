// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the S3 data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TransformS3DataSource {
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. Amazon SageMaker uses all objects with the specified key name prefix for batch transform.</p>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want Amazon SageMaker to use for batch transform.</p>
    /// <p>The following values are compatible: <code>ManifestFile</code>, <code>S3Prefix</code></p>
    /// <p>The following value is not compatible: <code>AugmentedManifestFile</code></p>
    pub s3_data_type: ::std::option::Option<crate::types::S3DataType>,
    /// <p>Depending on the value specified for the <code>S3DataType</code>, identifies either a key name prefix or a manifest. For example:</p>
    /// <ul>
    /// <li>
    /// <p>A key name prefix might look like this: <code>s3://bucketname/exampleprefix/</code>.</p></li>
    /// <li>
    /// <p>A manifest might look like this: <code>s3://bucketname/example.manifest</code></p>
    /// <p>The manifest is an S3 object which is a JSON file with the following format:</p>
    /// <p><code>\[ {"prefix": "s3://customer_bucket/some/prefix/"},</code></p>
    /// <p><code>"relative/path/to/custdata-1",</code></p>
    /// <p><code>"relative/path/custdata-2",</code></p>
    /// <p><code>...</code></p>
    /// <p><code>"relative/path/custdata-N"</code></p>
    /// <p><code>\]</code></p>
    /// <p>The preceding JSON matches the following <code>S3Uris</code>:</p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/to/custdata-1</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-2</code></p>
    /// <p><code>...</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-N</code></p>
    /// <p>The complete set of <code>S3Uris</code> in this manifest constitutes the input data for the channel for this datasource. The object that each <code>S3Uris</code> points to must be readable by the IAM role that Amazon SageMaker uses to perform tasks on your behalf.</p></li>
    /// </ul>
    pub s3_uri: ::std::option::Option<::std::string::String>,
}
impl TransformS3DataSource {
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. Amazon SageMaker uses all objects with the specified key name prefix for batch transform.</p>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want Amazon SageMaker to use for batch transform.</p>
    /// <p>The following values are compatible: <code>ManifestFile</code>, <code>S3Prefix</code></p>
    /// <p>The following value is not compatible: <code>AugmentedManifestFile</code></p>
    pub fn s3_data_type(&self) -> ::std::option::Option<&crate::types::S3DataType> {
        self.s3_data_type.as_ref()
    }
    /// <p>Depending on the value specified for the <code>S3DataType</code>, identifies either a key name prefix or a manifest. For example:</p>
    /// <ul>
    /// <li>
    /// <p>A key name prefix might look like this: <code>s3://bucketname/exampleprefix/</code>.</p></li>
    /// <li>
    /// <p>A manifest might look like this: <code>s3://bucketname/example.manifest</code></p>
    /// <p>The manifest is an S3 object which is a JSON file with the following format:</p>
    /// <p><code>\[ {"prefix": "s3://customer_bucket/some/prefix/"},</code></p>
    /// <p><code>"relative/path/to/custdata-1",</code></p>
    /// <p><code>"relative/path/custdata-2",</code></p>
    /// <p><code>...</code></p>
    /// <p><code>"relative/path/custdata-N"</code></p>
    /// <p><code>\]</code></p>
    /// <p>The preceding JSON matches the following <code>S3Uris</code>:</p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/to/custdata-1</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-2</code></p>
    /// <p><code>...</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-N</code></p>
    /// <p>The complete set of <code>S3Uris</code> in this manifest constitutes the input data for the channel for this datasource. The object that each <code>S3Uris</code> points to must be readable by the IAM role that Amazon SageMaker uses to perform tasks on your behalf.</p></li>
    /// </ul>
    pub fn s3_uri(&self) -> ::std::option::Option<&str> {
        self.s3_uri.as_deref()
    }
}
impl TransformS3DataSource {
    /// Creates a new builder-style object to manufacture [`TransformS3DataSource`](crate::types::TransformS3DataSource).
    pub fn builder() -> crate::types::builders::TransformS3DataSourceBuilder {
        crate::types::builders::TransformS3DataSourceBuilder::default()
    }
}

/// A builder for [`TransformS3DataSource`](crate::types::TransformS3DataSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TransformS3DataSourceBuilder {
    pub(crate) s3_data_type: ::std::option::Option<crate::types::S3DataType>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
}
impl TransformS3DataSourceBuilder {
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. Amazon SageMaker uses all objects with the specified key name prefix for batch transform.</p>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want Amazon SageMaker to use for batch transform.</p>
    /// <p>The following values are compatible: <code>ManifestFile</code>, <code>S3Prefix</code></p>
    /// <p>The following value is not compatible: <code>AugmentedManifestFile</code></p>
    /// This field is required.
    pub fn s3_data_type(mut self, input: crate::types::S3DataType) -> Self {
        self.s3_data_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. Amazon SageMaker uses all objects with the specified key name prefix for batch transform.</p>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want Amazon SageMaker to use for batch transform.</p>
    /// <p>The following values are compatible: <code>ManifestFile</code>, <code>S3Prefix</code></p>
    /// <p>The following value is not compatible: <code>AugmentedManifestFile</code></p>
    pub fn set_s3_data_type(mut self, input: ::std::option::Option<crate::types::S3DataType>) -> Self {
        self.s3_data_type = input;
        self
    }
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. Amazon SageMaker uses all objects with the specified key name prefix for batch transform.</p>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want Amazon SageMaker to use for batch transform.</p>
    /// <p>The following values are compatible: <code>ManifestFile</code>, <code>S3Prefix</code></p>
    /// <p>The following value is not compatible: <code>AugmentedManifestFile</code></p>
    pub fn get_s3_data_type(&self) -> &::std::option::Option<crate::types::S3DataType> {
        &self.s3_data_type
    }
    /// <p>Depending on the value specified for the <code>S3DataType</code>, identifies either a key name prefix or a manifest. For example:</p>
    /// <ul>
    /// <li>
    /// <p>A key name prefix might look like this: <code>s3://bucketname/exampleprefix/</code>.</p></li>
    /// <li>
    /// <p>A manifest might look like this: <code>s3://bucketname/example.manifest</code></p>
    /// <p>The manifest is an S3 object which is a JSON file with the following format:</p>
    /// <p><code>\[ {"prefix": "s3://customer_bucket/some/prefix/"},</code></p>
    /// <p><code>"relative/path/to/custdata-1",</code></p>
    /// <p><code>"relative/path/custdata-2",</code></p>
    /// <p><code>...</code></p>
    /// <p><code>"relative/path/custdata-N"</code></p>
    /// <p><code>\]</code></p>
    /// <p>The preceding JSON matches the following <code>S3Uris</code>:</p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/to/custdata-1</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-2</code></p>
    /// <p><code>...</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-N</code></p>
    /// <p>The complete set of <code>S3Uris</code> in this manifest constitutes the input data for the channel for this datasource. The object that each <code>S3Uris</code> points to must be readable by the IAM role that Amazon SageMaker uses to perform tasks on your behalf.</p></li>
    /// </ul>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Depending on the value specified for the <code>S3DataType</code>, identifies either a key name prefix or a manifest. For example:</p>
    /// <ul>
    /// <li>
    /// <p>A key name prefix might look like this: <code>s3://bucketname/exampleprefix/</code>.</p></li>
    /// <li>
    /// <p>A manifest might look like this: <code>s3://bucketname/example.manifest</code></p>
    /// <p>The manifest is an S3 object which is a JSON file with the following format:</p>
    /// <p><code>\[ {"prefix": "s3://customer_bucket/some/prefix/"},</code></p>
    /// <p><code>"relative/path/to/custdata-1",</code></p>
    /// <p><code>"relative/path/custdata-2",</code></p>
    /// <p><code>...</code></p>
    /// <p><code>"relative/path/custdata-N"</code></p>
    /// <p><code>\]</code></p>
    /// <p>The preceding JSON matches the following <code>S3Uris</code>:</p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/to/custdata-1</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-2</code></p>
    /// <p><code>...</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-N</code></p>
    /// <p>The complete set of <code>S3Uris</code> in this manifest constitutes the input data for the channel for this datasource. The object that each <code>S3Uris</code> points to must be readable by the IAM role that Amazon SageMaker uses to perform tasks on your behalf.</p></li>
    /// </ul>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>Depending on the value specified for the <code>S3DataType</code>, identifies either a key name prefix or a manifest. For example:</p>
    /// <ul>
    /// <li>
    /// <p>A key name prefix might look like this: <code>s3://bucketname/exampleprefix/</code>.</p></li>
    /// <li>
    /// <p>A manifest might look like this: <code>s3://bucketname/example.manifest</code></p>
    /// <p>The manifest is an S3 object which is a JSON file with the following format:</p>
    /// <p><code>\[ {"prefix": "s3://customer_bucket/some/prefix/"},</code></p>
    /// <p><code>"relative/path/to/custdata-1",</code></p>
    /// <p><code>"relative/path/custdata-2",</code></p>
    /// <p><code>...</code></p>
    /// <p><code>"relative/path/custdata-N"</code></p>
    /// <p><code>\]</code></p>
    /// <p>The preceding JSON matches the following <code>S3Uris</code>:</p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/to/custdata-1</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-2</code></p>
    /// <p><code>...</code></p>
    /// <p><code>s3://customer_bucket/some/prefix/relative/path/custdata-N</code></p>
    /// <p>The complete set of <code>S3Uris</code> in this manifest constitutes the input data for the channel for this datasource. The object that each <code>S3Uris</code> points to must be readable by the IAM role that Amazon SageMaker uses to perform tasks on your behalf.</p></li>
    /// </ul>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// Consumes the builder and constructs a [`TransformS3DataSource`](crate::types::TransformS3DataSource).
    pub fn build(self) -> crate::types::TransformS3DataSource {
        crate::types::TransformS3DataSource {
            s3_data_type: self.s3_data_type,
            s3_uri: self.s3_uri,
        }
    }
}
