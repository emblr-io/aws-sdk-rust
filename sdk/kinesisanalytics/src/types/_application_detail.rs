// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This documentation is for version 1 of the Amazon Kinesis Data Analytics API, which only supports SQL applications. Version 2 of the API supports SQL and Java applications. For more information about version 2, see <a href="/kinesisanalytics/latest/apiv2/Welcome.html">Amazon Kinesis Data Analytics API V2 Documentation</a>.</p>
/// </note>
/// <p>Provides a description of the application, including the application Amazon Resource Name (ARN), status, latest version, and input and output configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplicationDetail {
    /// <p>Name of the application.</p>
    pub application_name: ::std::string::String,
    /// <p>Description of the application.</p>
    pub application_description: ::std::option::Option<::std::string::String>,
    /// <p>ARN of the application.</p>
    pub application_arn: ::std::string::String,
    /// <p>Status of the application.</p>
    pub application_status: crate::types::ApplicationStatus,
    /// <p>Time stamp when the application version was created.</p>
    pub create_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Time stamp when the application was last updated.</p>
    pub last_update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Describes the application input configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub input_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::InputDescription>>,
    /// <p>Describes the application output configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-output.html">Configuring Application Output</a>.</p>
    pub output_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::OutputDescription>>,
    /// <p>Describes reference data sources configured for the application. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub reference_data_source_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::ReferenceDataSourceDescription>>,
    /// <p>Describes the CloudWatch log streams that are configured to receive application messages. For more information about using CloudWatch log streams with Amazon Kinesis Analytics applications, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/cloudwatch-logs.html">Working with Amazon CloudWatch Logs</a>.</p>
    pub cloud_watch_logging_option_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchLoggingOptionDescription>>,
    /// <p>Returns the application code that you provided to perform data analysis on any of the in-application streams in your application.</p>
    pub application_code: ::std::option::Option<::std::string::String>,
    /// <p>Provides the current application version.</p>
    pub application_version_id: i64,
}
impl ApplicationDetail {
    /// <p>Name of the application.</p>
    pub fn application_name(&self) -> &str {
        use std::ops::Deref;
        self.application_name.deref()
    }
    /// <p>Description of the application.</p>
    pub fn application_description(&self) -> ::std::option::Option<&str> {
        self.application_description.as_deref()
    }
    /// <p>ARN of the application.</p>
    pub fn application_arn(&self) -> &str {
        use std::ops::Deref;
        self.application_arn.deref()
    }
    /// <p>Status of the application.</p>
    pub fn application_status(&self) -> &crate::types::ApplicationStatus {
        &self.application_status
    }
    /// <p>Time stamp when the application version was created.</p>
    pub fn create_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_timestamp.as_ref()
    }
    /// <p>Time stamp when the application was last updated.</p>
    pub fn last_update_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_timestamp.as_ref()
    }
    /// <p>Describes the application input configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.input_descriptions.is_none()`.
    pub fn input_descriptions(&self) -> &[crate::types::InputDescription] {
        self.input_descriptions.as_deref().unwrap_or_default()
    }
    /// <p>Describes the application output configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-output.html">Configuring Application Output</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.output_descriptions.is_none()`.
    pub fn output_descriptions(&self) -> &[crate::types::OutputDescription] {
        self.output_descriptions.as_deref().unwrap_or_default()
    }
    /// <p>Describes reference data sources configured for the application. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reference_data_source_descriptions.is_none()`.
    pub fn reference_data_source_descriptions(&self) -> &[crate::types::ReferenceDataSourceDescription] {
        self.reference_data_source_descriptions.as_deref().unwrap_or_default()
    }
    /// <p>Describes the CloudWatch log streams that are configured to receive application messages. For more information about using CloudWatch log streams with Amazon Kinesis Analytics applications, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/cloudwatch-logs.html">Working with Amazon CloudWatch Logs</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cloud_watch_logging_option_descriptions.is_none()`.
    pub fn cloud_watch_logging_option_descriptions(&self) -> &[crate::types::CloudWatchLoggingOptionDescription] {
        self.cloud_watch_logging_option_descriptions.as_deref().unwrap_or_default()
    }
    /// <p>Returns the application code that you provided to perform data analysis on any of the in-application streams in your application.</p>
    pub fn application_code(&self) -> ::std::option::Option<&str> {
        self.application_code.as_deref()
    }
    /// <p>Provides the current application version.</p>
    pub fn application_version_id(&self) -> i64 {
        self.application_version_id
    }
}
impl ApplicationDetail {
    /// Creates a new builder-style object to manufacture [`ApplicationDetail`](crate::types::ApplicationDetail).
    pub fn builder() -> crate::types::builders::ApplicationDetailBuilder {
        crate::types::builders::ApplicationDetailBuilder::default()
    }
}

/// A builder for [`ApplicationDetail`](crate::types::ApplicationDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationDetailBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) application_description: ::std::option::Option<::std::string::String>,
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_status: ::std::option::Option<crate::types::ApplicationStatus>,
    pub(crate) create_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) input_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::InputDescription>>,
    pub(crate) output_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::OutputDescription>>,
    pub(crate) reference_data_source_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::ReferenceDataSourceDescription>>,
    pub(crate) cloud_watch_logging_option_descriptions: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchLoggingOptionDescription>>,
    pub(crate) application_code: ::std::option::Option<::std::string::String>,
    pub(crate) application_version_id: ::std::option::Option<i64>,
}
impl ApplicationDetailBuilder {
    /// <p>Name of the application.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the application.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>Name of the application.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>Description of the application.</p>
    pub fn application_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Description of the application.</p>
    pub fn set_application_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_description = input;
        self
    }
    /// <p>Description of the application.</p>
    pub fn get_application_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_description
    }
    /// <p>ARN of the application.</p>
    /// This field is required.
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>ARN of the application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>Status of the application.</p>
    /// This field is required.
    pub fn application_status(mut self, input: crate::types::ApplicationStatus) -> Self {
        self.application_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the application.</p>
    pub fn set_application_status(mut self, input: ::std::option::Option<crate::types::ApplicationStatus>) -> Self {
        self.application_status = input;
        self
    }
    /// <p>Status of the application.</p>
    pub fn get_application_status(&self) -> &::std::option::Option<crate::types::ApplicationStatus> {
        &self.application_status
    }
    /// <p>Time stamp when the application version was created.</p>
    pub fn create_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time stamp when the application version was created.</p>
    pub fn set_create_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_timestamp = input;
        self
    }
    /// <p>Time stamp when the application version was created.</p>
    pub fn get_create_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_timestamp
    }
    /// <p>Time stamp when the application was last updated.</p>
    pub fn last_update_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time stamp when the application was last updated.</p>
    pub fn set_last_update_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_timestamp = input;
        self
    }
    /// <p>Time stamp when the application was last updated.</p>
    pub fn get_last_update_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_timestamp
    }
    /// Appends an item to `input_descriptions`.
    ///
    /// To override the contents of this collection use [`set_input_descriptions`](Self::set_input_descriptions).
    ///
    /// <p>Describes the application input configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn input_descriptions(mut self, input: crate::types::InputDescription) -> Self {
        let mut v = self.input_descriptions.unwrap_or_default();
        v.push(input);
        self.input_descriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the application input configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn set_input_descriptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InputDescription>>) -> Self {
        self.input_descriptions = input;
        self
    }
    /// <p>Describes the application input configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn get_input_descriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InputDescription>> {
        &self.input_descriptions
    }
    /// Appends an item to `output_descriptions`.
    ///
    /// To override the contents of this collection use [`set_output_descriptions`](Self::set_output_descriptions).
    ///
    /// <p>Describes the application output configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-output.html">Configuring Application Output</a>.</p>
    pub fn output_descriptions(mut self, input: crate::types::OutputDescription) -> Self {
        let mut v = self.output_descriptions.unwrap_or_default();
        v.push(input);
        self.output_descriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the application output configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-output.html">Configuring Application Output</a>.</p>
    pub fn set_output_descriptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OutputDescription>>) -> Self {
        self.output_descriptions = input;
        self
    }
    /// <p>Describes the application output configuration. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-output.html">Configuring Application Output</a>.</p>
    pub fn get_output_descriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OutputDescription>> {
        &self.output_descriptions
    }
    /// Appends an item to `reference_data_source_descriptions`.
    ///
    /// To override the contents of this collection use [`set_reference_data_source_descriptions`](Self::set_reference_data_source_descriptions).
    ///
    /// <p>Describes reference data sources configured for the application. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn reference_data_source_descriptions(mut self, input: crate::types::ReferenceDataSourceDescription) -> Self {
        let mut v = self.reference_data_source_descriptions.unwrap_or_default();
        v.push(input);
        self.reference_data_source_descriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes reference data sources configured for the application. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn set_reference_data_source_descriptions(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ReferenceDataSourceDescription>>,
    ) -> Self {
        self.reference_data_source_descriptions = input;
        self
    }
    /// <p>Describes reference data sources configured for the application. For more information, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/how-it-works-input.html">Configuring Application Input</a>.</p>
    pub fn get_reference_data_source_descriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReferenceDataSourceDescription>> {
        &self.reference_data_source_descriptions
    }
    /// Appends an item to `cloud_watch_logging_option_descriptions`.
    ///
    /// To override the contents of this collection use [`set_cloud_watch_logging_option_descriptions`](Self::set_cloud_watch_logging_option_descriptions).
    ///
    /// <p>Describes the CloudWatch log streams that are configured to receive application messages. For more information about using CloudWatch log streams with Amazon Kinesis Analytics applications, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/cloudwatch-logs.html">Working with Amazon CloudWatch Logs</a>.</p>
    pub fn cloud_watch_logging_option_descriptions(mut self, input: crate::types::CloudWatchLoggingOptionDescription) -> Self {
        let mut v = self.cloud_watch_logging_option_descriptions.unwrap_or_default();
        v.push(input);
        self.cloud_watch_logging_option_descriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the CloudWatch log streams that are configured to receive application messages. For more information about using CloudWatch log streams with Amazon Kinesis Analytics applications, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/cloudwatch-logs.html">Working with Amazon CloudWatch Logs</a>.</p>
    pub fn set_cloud_watch_logging_option_descriptions(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchLoggingOptionDescription>>,
    ) -> Self {
        self.cloud_watch_logging_option_descriptions = input;
        self
    }
    /// <p>Describes the CloudWatch log streams that are configured to receive application messages. For more information about using CloudWatch log streams with Amazon Kinesis Analytics applications, see <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/cloudwatch-logs.html">Working with Amazon CloudWatch Logs</a>.</p>
    pub fn get_cloud_watch_logging_option_descriptions(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::CloudWatchLoggingOptionDescription>> {
        &self.cloud_watch_logging_option_descriptions
    }
    /// <p>Returns the application code that you provided to perform data analysis on any of the in-application streams in your application.</p>
    pub fn application_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the application code that you provided to perform data analysis on any of the in-application streams in your application.</p>
    pub fn set_application_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_code = input;
        self
    }
    /// <p>Returns the application code that you provided to perform data analysis on any of the in-application streams in your application.</p>
    pub fn get_application_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_code
    }
    /// <p>Provides the current application version.</p>
    /// This field is required.
    pub fn application_version_id(mut self, input: i64) -> Self {
        self.application_version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the current application version.</p>
    pub fn set_application_version_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.application_version_id = input;
        self
    }
    /// <p>Provides the current application version.</p>
    pub fn get_application_version_id(&self) -> &::std::option::Option<i64> {
        &self.application_version_id
    }
    /// Consumes the builder and constructs a [`ApplicationDetail`](crate::types::ApplicationDetail).
    /// This method will fail if any of the following fields are not set:
    /// - [`application_name`](crate::types::builders::ApplicationDetailBuilder::application_name)
    /// - [`application_arn`](crate::types::builders::ApplicationDetailBuilder::application_arn)
    /// - [`application_status`](crate::types::builders::ApplicationDetailBuilder::application_status)
    /// - [`application_version_id`](crate::types::builders::ApplicationDetailBuilder::application_version_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ApplicationDetail, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ApplicationDetail {
            application_name: self.application_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_name",
                    "application_name was not specified but it is required when building ApplicationDetail",
                )
            })?,
            application_description: self.application_description,
            application_arn: self.application_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_arn",
                    "application_arn was not specified but it is required when building ApplicationDetail",
                )
            })?,
            application_status: self.application_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_status",
                    "application_status was not specified but it is required when building ApplicationDetail",
                )
            })?,
            create_timestamp: self.create_timestamp,
            last_update_timestamp: self.last_update_timestamp,
            input_descriptions: self.input_descriptions,
            output_descriptions: self.output_descriptions,
            reference_data_source_descriptions: self.reference_data_source_descriptions,
            cloud_watch_logging_option_descriptions: self.cloud_watch_logging_option_descriptions,
            application_code: self.application_code,
            application_version_id: self.application_version_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_version_id",
                    "application_version_id was not specified but it is required when building ApplicationDetail",
                )
            })?,
        })
    }
}
