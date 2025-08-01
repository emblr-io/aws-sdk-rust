// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddApplicationReferenceDataSourceInput {
    /// <p>Name of an existing application.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>Version of the application for which you are adding the reference data source. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub current_application_version_id: ::std::option::Option<i64>,
    /// <p>The reference data source can be an object in your Amazon S3 bucket. Amazon Kinesis Analytics reads the object and copies the data into the in-application table that is created. You provide an S3 bucket, object key name, and the resulting in-application table that is created. You must also provide an IAM role with the necessary permissions that Amazon Kinesis Analytics can assume to read the object from your S3 bucket on your behalf.</p>
    pub reference_data_source: ::std::option::Option<crate::types::ReferenceDataSource>,
}
impl AddApplicationReferenceDataSourceInput {
    /// <p>Name of an existing application.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>Version of the application for which you are adding the reference data source. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn current_application_version_id(&self) -> ::std::option::Option<i64> {
        self.current_application_version_id
    }
    /// <p>The reference data source can be an object in your Amazon S3 bucket. Amazon Kinesis Analytics reads the object and copies the data into the in-application table that is created. You provide an S3 bucket, object key name, and the resulting in-application table that is created. You must also provide an IAM role with the necessary permissions that Amazon Kinesis Analytics can assume to read the object from your S3 bucket on your behalf.</p>
    pub fn reference_data_source(&self) -> ::std::option::Option<&crate::types::ReferenceDataSource> {
        self.reference_data_source.as_ref()
    }
}
impl AddApplicationReferenceDataSourceInput {
    /// Creates a new builder-style object to manufacture [`AddApplicationReferenceDataSourceInput`](crate::operation::add_application_reference_data_source::AddApplicationReferenceDataSourceInput).
    pub fn builder() -> crate::operation::add_application_reference_data_source::builders::AddApplicationReferenceDataSourceInputBuilder {
        crate::operation::add_application_reference_data_source::builders::AddApplicationReferenceDataSourceInputBuilder::default()
    }
}

/// A builder for [`AddApplicationReferenceDataSourceInput`](crate::operation::add_application_reference_data_source::AddApplicationReferenceDataSourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddApplicationReferenceDataSourceInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) current_application_version_id: ::std::option::Option<i64>,
    pub(crate) reference_data_source: ::std::option::Option<crate::types::ReferenceDataSource>,
}
impl AddApplicationReferenceDataSourceInputBuilder {
    /// <p>Name of an existing application.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of an existing application.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>Name of an existing application.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>Version of the application for which you are adding the reference data source. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    /// This field is required.
    pub fn current_application_version_id(mut self, input: i64) -> Self {
        self.current_application_version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Version of the application for which you are adding the reference data source. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn set_current_application_version_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.current_application_version_id = input;
        self
    }
    /// <p>Version of the application for which you are adding the reference data source. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn get_current_application_version_id(&self) -> &::std::option::Option<i64> {
        &self.current_application_version_id
    }
    /// <p>The reference data source can be an object in your Amazon S3 bucket. Amazon Kinesis Analytics reads the object and copies the data into the in-application table that is created. You provide an S3 bucket, object key name, and the resulting in-application table that is created. You must also provide an IAM role with the necessary permissions that Amazon Kinesis Analytics can assume to read the object from your S3 bucket on your behalf.</p>
    /// This field is required.
    pub fn reference_data_source(mut self, input: crate::types::ReferenceDataSource) -> Self {
        self.reference_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reference data source can be an object in your Amazon S3 bucket. Amazon Kinesis Analytics reads the object and copies the data into the in-application table that is created. You provide an S3 bucket, object key name, and the resulting in-application table that is created. You must also provide an IAM role with the necessary permissions that Amazon Kinesis Analytics can assume to read the object from your S3 bucket on your behalf.</p>
    pub fn set_reference_data_source(mut self, input: ::std::option::Option<crate::types::ReferenceDataSource>) -> Self {
        self.reference_data_source = input;
        self
    }
    /// <p>The reference data source can be an object in your Amazon S3 bucket. Amazon Kinesis Analytics reads the object and copies the data into the in-application table that is created. You provide an S3 bucket, object key name, and the resulting in-application table that is created. You must also provide an IAM role with the necessary permissions that Amazon Kinesis Analytics can assume to read the object from your S3 bucket on your behalf.</p>
    pub fn get_reference_data_source(&self) -> &::std::option::Option<crate::types::ReferenceDataSource> {
        &self.reference_data_source
    }
    /// Consumes the builder and constructs a [`AddApplicationReferenceDataSourceInput`](crate::operation::add_application_reference_data_source::AddApplicationReferenceDataSourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::add_application_reference_data_source::AddApplicationReferenceDataSourceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::add_application_reference_data_source::AddApplicationReferenceDataSourceInput {
                application_name: self.application_name,
                current_application_version_id: self.current_application_version_id,
                reference_data_source: self.reference_data_source,
            },
        )
    }
}
