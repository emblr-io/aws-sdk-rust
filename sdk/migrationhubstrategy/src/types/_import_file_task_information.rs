// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the import file tasks you request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportFileTaskInformation {
    /// <p>The ID of the import file task.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Status of import file task.</p>
    pub status: ::std::option::Option<crate::types::ImportFileTaskStatus>,
    /// <p>Start time of the import task.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The S3 bucket where the import file is located.</p>
    pub input_s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 key name of the import file.</p>
    pub input_s3_key: ::std::option::Option<::std::string::String>,
    /// <p>The S3 bucket name for status report of import task.</p>
    pub status_report_s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 key name for status report of import task. The report contains details about whether each record imported successfully or why it did not.</p>
    pub status_report_s3_key: ::std::option::Option<::std::string::String>,
    /// <p>The time that the import task completes.</p>
    pub completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of records successfully imported.</p>
    pub number_of_records_success: ::std::option::Option<i32>,
    /// <p>The number of records that failed to be imported.</p>
    pub number_of_records_failed: ::std::option::Option<i32>,
    /// <p>The name of the import task given in <code>StartImportFileTask</code>.</p>
    pub import_name: ::std::option::Option<::std::string::String>,
}
impl ImportFileTaskInformation {
    /// <p>The ID of the import file task.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Status of import file task.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ImportFileTaskStatus> {
        self.status.as_ref()
    }
    /// <p>Start time of the import task.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The S3 bucket where the import file is located.</p>
    pub fn input_s3_bucket(&self) -> ::std::option::Option<&str> {
        self.input_s3_bucket.as_deref()
    }
    /// <p>The Amazon S3 key name of the import file.</p>
    pub fn input_s3_key(&self) -> ::std::option::Option<&str> {
        self.input_s3_key.as_deref()
    }
    /// <p>The S3 bucket name for status report of import task.</p>
    pub fn status_report_s3_bucket(&self) -> ::std::option::Option<&str> {
        self.status_report_s3_bucket.as_deref()
    }
    /// <p>The Amazon S3 key name for status report of import task. The report contains details about whether each record imported successfully or why it did not.</p>
    pub fn status_report_s3_key(&self) -> ::std::option::Option<&str> {
        self.status_report_s3_key.as_deref()
    }
    /// <p>The time that the import task completes.</p>
    pub fn completion_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_time.as_ref()
    }
    /// <p>The number of records successfully imported.</p>
    pub fn number_of_records_success(&self) -> ::std::option::Option<i32> {
        self.number_of_records_success
    }
    /// <p>The number of records that failed to be imported.</p>
    pub fn number_of_records_failed(&self) -> ::std::option::Option<i32> {
        self.number_of_records_failed
    }
    /// <p>The name of the import task given in <code>StartImportFileTask</code>.</p>
    pub fn import_name(&self) -> ::std::option::Option<&str> {
        self.import_name.as_deref()
    }
}
impl ImportFileTaskInformation {
    /// Creates a new builder-style object to manufacture [`ImportFileTaskInformation`](crate::types::ImportFileTaskInformation).
    pub fn builder() -> crate::types::builders::ImportFileTaskInformationBuilder {
        crate::types::builders::ImportFileTaskInformationBuilder::default()
    }
}

/// A builder for [`ImportFileTaskInformation`](crate::types::ImportFileTaskInformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportFileTaskInformationBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ImportFileTaskStatus>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) input_s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) input_s3_key: ::std::option::Option<::std::string::String>,
    pub(crate) status_report_s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) status_report_s3_key: ::std::option::Option<::std::string::String>,
    pub(crate) completion_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) number_of_records_success: ::std::option::Option<i32>,
    pub(crate) number_of_records_failed: ::std::option::Option<i32>,
    pub(crate) import_name: ::std::option::Option<::std::string::String>,
}
impl ImportFileTaskInformationBuilder {
    /// <p>The ID of the import file task.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the import file task.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the import file task.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Status of import file task.</p>
    pub fn status(mut self, input: crate::types::ImportFileTaskStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of import file task.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ImportFileTaskStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Status of import file task.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ImportFileTaskStatus> {
        &self.status
    }
    /// <p>Start time of the import task.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Start time of the import task.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Start time of the import task.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The S3 bucket where the import file is located.</p>
    pub fn input_s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 bucket where the import file is located.</p>
    pub fn set_input_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_s3_bucket = input;
        self
    }
    /// <p>The S3 bucket where the import file is located.</p>
    pub fn get_input_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_s3_bucket
    }
    /// <p>The Amazon S3 key name of the import file.</p>
    pub fn input_s3_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_s3_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 key name of the import file.</p>
    pub fn set_input_s3_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_s3_key = input;
        self
    }
    /// <p>The Amazon S3 key name of the import file.</p>
    pub fn get_input_s3_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_s3_key
    }
    /// <p>The S3 bucket name for status report of import task.</p>
    pub fn status_report_s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_report_s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 bucket name for status report of import task.</p>
    pub fn set_status_report_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_report_s3_bucket = input;
        self
    }
    /// <p>The S3 bucket name for status report of import task.</p>
    pub fn get_status_report_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_report_s3_bucket
    }
    /// <p>The Amazon S3 key name for status report of import task. The report contains details about whether each record imported successfully or why it did not.</p>
    pub fn status_report_s3_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_report_s3_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 key name for status report of import task. The report contains details about whether each record imported successfully or why it did not.</p>
    pub fn set_status_report_s3_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_report_s3_key = input;
        self
    }
    /// <p>The Amazon S3 key name for status report of import task. The report contains details about whether each record imported successfully or why it did not.</p>
    pub fn get_status_report_s3_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_report_s3_key
    }
    /// <p>The time that the import task completes.</p>
    pub fn completion_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the import task completes.</p>
    pub fn set_completion_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_time = input;
        self
    }
    /// <p>The time that the import task completes.</p>
    pub fn get_completion_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_time
    }
    /// <p>The number of records successfully imported.</p>
    pub fn number_of_records_success(mut self, input: i32) -> Self {
        self.number_of_records_success = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of records successfully imported.</p>
    pub fn set_number_of_records_success(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_records_success = input;
        self
    }
    /// <p>The number of records successfully imported.</p>
    pub fn get_number_of_records_success(&self) -> &::std::option::Option<i32> {
        &self.number_of_records_success
    }
    /// <p>The number of records that failed to be imported.</p>
    pub fn number_of_records_failed(mut self, input: i32) -> Self {
        self.number_of_records_failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of records that failed to be imported.</p>
    pub fn set_number_of_records_failed(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_records_failed = input;
        self
    }
    /// <p>The number of records that failed to be imported.</p>
    pub fn get_number_of_records_failed(&self) -> &::std::option::Option<i32> {
        &self.number_of_records_failed
    }
    /// <p>The name of the import task given in <code>StartImportFileTask</code>.</p>
    pub fn import_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.import_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the import task given in <code>StartImportFileTask</code>.</p>
    pub fn set_import_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.import_name = input;
        self
    }
    /// <p>The name of the import task given in <code>StartImportFileTask</code>.</p>
    pub fn get_import_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.import_name
    }
    /// Consumes the builder and constructs a [`ImportFileTaskInformation`](crate::types::ImportFileTaskInformation).
    pub fn build(self) -> crate::types::ImportFileTaskInformation {
        crate::types::ImportFileTaskInformation {
            id: self.id,
            status: self.status,
            start_time: self.start_time,
            input_s3_bucket: self.input_s3_bucket,
            input_s3_key: self.input_s3_key,
            status_report_s3_bucket: self.status_report_s3_bucket,
            status_report_s3_key: self.status_report_s3_key,
            completion_time: self.completion_time,
            number_of_records_success: self.number_of_records_success,
            number_of_records_failed: self.number_of_records_failed,
            import_name: self.import_name,
        }
    }
}
