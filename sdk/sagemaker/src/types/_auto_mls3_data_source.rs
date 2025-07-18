// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Amazon S3 data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoMls3DataSource {
    /// <p>The data type.</p>
    /// <ul>
    /// <li>
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. SageMaker AI uses all objects that match the specified key name prefix for model training.</p>
    /// <p>The <code>S3Prefix</code> should have the following format:</p>
    /// <p><code>s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER-OR-FILE</code></p></li>
    /// <li>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want SageMaker AI to use for model training.</p>
    /// <p>A <code>ManifestFile</code> should have the format shown below:</p>
    /// <p><code>\[ {"prefix": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/DOC-EXAMPLE-PREFIX/"},</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-1",</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-2",</code></p>
    /// <p><code>... "DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-N" \]</code></p></li>
    /// <li>
    /// <p>If you choose <code>AugmentedManifestFile</code>, <code>S3Uri</code> identifies an object that is an augmented manifest file in JSON lines format. This file contains the data you want to use for model training. <code>AugmentedManifestFile</code> is available for V2 API jobs only (for example, for jobs created by calling <code>CreateAutoMLJobV2</code>).</p>
    /// <p>Here is a minimal, single-record example of an <code>AugmentedManifestFile</code>:</p>
    /// <p><code>{"source-ref": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/cats/cat.jpg",</code></p>
    /// <p><code>"label-metadata": {"class-name": "cat"</code> }</p>
    /// <p>For more information on <code>AugmentedManifestFile</code>, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/augmented-manifest.html">Provide Dataset Metadata to Training Jobs with an Augmented Manifest File</a>.</p></li>
    /// </ul>
    pub s3_data_type: ::std::option::Option<crate::types::AutoMls3DataType>,
    /// <p>The URL to the Amazon S3 data source. The Uri refers to the Amazon S3 prefix or ManifestFile depending on the data type.</p>
    pub s3_uri: ::std::option::Option<::std::string::String>,
}
impl AutoMls3DataSource {
    /// <p>The data type.</p>
    /// <ul>
    /// <li>
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. SageMaker AI uses all objects that match the specified key name prefix for model training.</p>
    /// <p>The <code>S3Prefix</code> should have the following format:</p>
    /// <p><code>s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER-OR-FILE</code></p></li>
    /// <li>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want SageMaker AI to use for model training.</p>
    /// <p>A <code>ManifestFile</code> should have the format shown below:</p>
    /// <p><code>\[ {"prefix": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/DOC-EXAMPLE-PREFIX/"},</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-1",</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-2",</code></p>
    /// <p><code>... "DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-N" \]</code></p></li>
    /// <li>
    /// <p>If you choose <code>AugmentedManifestFile</code>, <code>S3Uri</code> identifies an object that is an augmented manifest file in JSON lines format. This file contains the data you want to use for model training. <code>AugmentedManifestFile</code> is available for V2 API jobs only (for example, for jobs created by calling <code>CreateAutoMLJobV2</code>).</p>
    /// <p>Here is a minimal, single-record example of an <code>AugmentedManifestFile</code>:</p>
    /// <p><code>{"source-ref": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/cats/cat.jpg",</code></p>
    /// <p><code>"label-metadata": {"class-name": "cat"</code> }</p>
    /// <p>For more information on <code>AugmentedManifestFile</code>, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/augmented-manifest.html">Provide Dataset Metadata to Training Jobs with an Augmented Manifest File</a>.</p></li>
    /// </ul>
    pub fn s3_data_type(&self) -> ::std::option::Option<&crate::types::AutoMls3DataType> {
        self.s3_data_type.as_ref()
    }
    /// <p>The URL to the Amazon S3 data source. The Uri refers to the Amazon S3 prefix or ManifestFile depending on the data type.</p>
    pub fn s3_uri(&self) -> ::std::option::Option<&str> {
        self.s3_uri.as_deref()
    }
}
impl AutoMls3DataSource {
    /// Creates a new builder-style object to manufacture [`AutoMls3DataSource`](crate::types::AutoMls3DataSource).
    pub fn builder() -> crate::types::builders::AutoMls3DataSourceBuilder {
        crate::types::builders::AutoMls3DataSourceBuilder::default()
    }
}

/// A builder for [`AutoMls3DataSource`](crate::types::AutoMls3DataSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoMls3DataSourceBuilder {
    pub(crate) s3_data_type: ::std::option::Option<crate::types::AutoMls3DataType>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
}
impl AutoMls3DataSourceBuilder {
    /// <p>The data type.</p>
    /// <ul>
    /// <li>
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. SageMaker AI uses all objects that match the specified key name prefix for model training.</p>
    /// <p>The <code>S3Prefix</code> should have the following format:</p>
    /// <p><code>s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER-OR-FILE</code></p></li>
    /// <li>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want SageMaker AI to use for model training.</p>
    /// <p>A <code>ManifestFile</code> should have the format shown below:</p>
    /// <p><code>\[ {"prefix": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/DOC-EXAMPLE-PREFIX/"},</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-1",</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-2",</code></p>
    /// <p><code>... "DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-N" \]</code></p></li>
    /// <li>
    /// <p>If you choose <code>AugmentedManifestFile</code>, <code>S3Uri</code> identifies an object that is an augmented manifest file in JSON lines format. This file contains the data you want to use for model training. <code>AugmentedManifestFile</code> is available for V2 API jobs only (for example, for jobs created by calling <code>CreateAutoMLJobV2</code>).</p>
    /// <p>Here is a minimal, single-record example of an <code>AugmentedManifestFile</code>:</p>
    /// <p><code>{"source-ref": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/cats/cat.jpg",</code></p>
    /// <p><code>"label-metadata": {"class-name": "cat"</code> }</p>
    /// <p>For more information on <code>AugmentedManifestFile</code>, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/augmented-manifest.html">Provide Dataset Metadata to Training Jobs with an Augmented Manifest File</a>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn s3_data_type(mut self, input: crate::types::AutoMls3DataType) -> Self {
        self.s3_data_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data type.</p>
    /// <ul>
    /// <li>
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. SageMaker AI uses all objects that match the specified key name prefix for model training.</p>
    /// <p>The <code>S3Prefix</code> should have the following format:</p>
    /// <p><code>s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER-OR-FILE</code></p></li>
    /// <li>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want SageMaker AI to use for model training.</p>
    /// <p>A <code>ManifestFile</code> should have the format shown below:</p>
    /// <p><code>\[ {"prefix": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/DOC-EXAMPLE-PREFIX/"},</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-1",</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-2",</code></p>
    /// <p><code>... "DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-N" \]</code></p></li>
    /// <li>
    /// <p>If you choose <code>AugmentedManifestFile</code>, <code>S3Uri</code> identifies an object that is an augmented manifest file in JSON lines format. This file contains the data you want to use for model training. <code>AugmentedManifestFile</code> is available for V2 API jobs only (for example, for jobs created by calling <code>CreateAutoMLJobV2</code>).</p>
    /// <p>Here is a minimal, single-record example of an <code>AugmentedManifestFile</code>:</p>
    /// <p><code>{"source-ref": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/cats/cat.jpg",</code></p>
    /// <p><code>"label-metadata": {"class-name": "cat"</code> }</p>
    /// <p>For more information on <code>AugmentedManifestFile</code>, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/augmented-manifest.html">Provide Dataset Metadata to Training Jobs with an Augmented Manifest File</a>.</p></li>
    /// </ul>
    pub fn set_s3_data_type(mut self, input: ::std::option::Option<crate::types::AutoMls3DataType>) -> Self {
        self.s3_data_type = input;
        self
    }
    /// <p>The data type.</p>
    /// <ul>
    /// <li>
    /// <p>If you choose <code>S3Prefix</code>, <code>S3Uri</code> identifies a key name prefix. SageMaker AI uses all objects that match the specified key name prefix for model training.</p>
    /// <p>The <code>S3Prefix</code> should have the following format:</p>
    /// <p><code>s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER-OR-FILE</code></p></li>
    /// <li>
    /// <p>If you choose <code>ManifestFile</code>, <code>S3Uri</code> identifies an object that is a manifest file containing a list of object keys that you want SageMaker AI to use for model training.</p>
    /// <p>A <code>ManifestFile</code> should have the format shown below:</p>
    /// <p><code>\[ {"prefix": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/DOC-EXAMPLE-PREFIX/"},</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-1",</code></p>
    /// <p><code>"DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-2",</code></p>
    /// <p><code>... "DOC-EXAMPLE-RELATIVE-PATH/DOC-EXAMPLE-FOLDER/DATA-N" \]</code></p></li>
    /// <li>
    /// <p>If you choose <code>AugmentedManifestFile</code>, <code>S3Uri</code> identifies an object that is an augmented manifest file in JSON lines format. This file contains the data you want to use for model training. <code>AugmentedManifestFile</code> is available for V2 API jobs only (for example, for jobs created by calling <code>CreateAutoMLJobV2</code>).</p>
    /// <p>Here is a minimal, single-record example of an <code>AugmentedManifestFile</code>:</p>
    /// <p><code>{"source-ref": "s3://DOC-EXAMPLE-BUCKET/DOC-EXAMPLE-FOLDER/cats/cat.jpg",</code></p>
    /// <p><code>"label-metadata": {"class-name": "cat"</code> }</p>
    /// <p>For more information on <code>AugmentedManifestFile</code>, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/augmented-manifest.html">Provide Dataset Metadata to Training Jobs with an Augmented Manifest File</a>.</p></li>
    /// </ul>
    pub fn get_s3_data_type(&self) -> &::std::option::Option<crate::types::AutoMls3DataType> {
        &self.s3_data_type
    }
    /// <p>The URL to the Amazon S3 data source. The Uri refers to the Amazon S3 prefix or ManifestFile depending on the data type.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL to the Amazon S3 data source. The Uri refers to the Amazon S3 prefix or ManifestFile depending on the data type.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The URL to the Amazon S3 data source. The Uri refers to the Amazon S3 prefix or ManifestFile depending on the data type.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// Consumes the builder and constructs a [`AutoMls3DataSource`](crate::types::AutoMls3DataSource).
    pub fn build(self) -> crate::types::AutoMls3DataSource {
        crate::types::AutoMls3DataSource {
            s3_data_type: self.s3_data_type,
            s3_uri: self.s3_uri,
        }
    }
}
