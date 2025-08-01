// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the configuration parameters for a job-completion report.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobReport {
    /// <p>The Amazon Resource Name (ARN) for the bucket where specified job-completion report will be stored.</p><note>
    /// <p><b>Directory buckets</b> - Directory buckets aren't supported as a location for Batch Operations to store job completion reports.</p>
    /// </note>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The format of the specified job-completion report.</p>
    pub format: ::std::option::Option<crate::types::JobReportFormat>,
    /// <p>Indicates whether the specified job will generate a job-completion report.</p>
    pub enabled: bool,
    /// <p>An optional prefix to describe where in the specified bucket the job-completion report will be stored. Amazon S3 stores the job-completion report at <code><prefix>
    /// /job-
    /// <job-id>
    /// /report.json
    /// </job-id>
    /// </prefix></code>.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the job-completion report will include details of all tasks or only failed tasks.</p>
    pub report_scope: ::std::option::Option<crate::types::JobReportScope>,
}
impl JobReport {
    /// <p>The Amazon Resource Name (ARN) for the bucket where specified job-completion report will be stored.</p><note>
    /// <p><b>Directory buckets</b> - Directory buckets aren't supported as a location for Batch Operations to store job completion reports.</p>
    /// </note>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The format of the specified job-completion report.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::JobReportFormat> {
        self.format.as_ref()
    }
    /// <p>Indicates whether the specified job will generate a job-completion report.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// <p>An optional prefix to describe where in the specified bucket the job-completion report will be stored. Amazon S3 stores the job-completion report at <code><prefix>
    /// /job-
    /// <job-id>
    /// /report.json
    /// </job-id>
    /// </prefix></code>.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>Indicates whether the job-completion report will include details of all tasks or only failed tasks.</p>
    pub fn report_scope(&self) -> ::std::option::Option<&crate::types::JobReportScope> {
        self.report_scope.as_ref()
    }
}
impl JobReport {
    /// Creates a new builder-style object to manufacture [`JobReport`](crate::types::JobReport).
    pub fn builder() -> crate::types::builders::JobReportBuilder {
        crate::types::builders::JobReportBuilder::default()
    }
}

/// A builder for [`JobReport`](crate::types::JobReport).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobReportBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) format: ::std::option::Option<crate::types::JobReportFormat>,
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) report_scope: ::std::option::Option<crate::types::JobReportScope>,
}
impl JobReportBuilder {
    /// <p>The Amazon Resource Name (ARN) for the bucket where specified job-completion report will be stored.</p><note>
    /// <p><b>Directory buckets</b> - Directory buckets aren't supported as a location for Batch Operations to store job completion reports.</p>
    /// </note>
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the bucket where specified job-completion report will be stored.</p><note>
    /// <p><b>Directory buckets</b> - Directory buckets aren't supported as a location for Batch Operations to store job completion reports.</p>
    /// </note>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the bucket where specified job-completion report will be stored.</p><note>
    /// <p><b>Directory buckets</b> - Directory buckets aren't supported as a location for Batch Operations to store job completion reports.</p>
    /// </note>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The format of the specified job-completion report.</p>
    pub fn format(mut self, input: crate::types::JobReportFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the specified job-completion report.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::JobReportFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the specified job-completion report.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::JobReportFormat> {
        &self.format
    }
    /// <p>Indicates whether the specified job will generate a job-completion report.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the specified job will generate a job-completion report.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Indicates whether the specified job will generate a job-completion report.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>An optional prefix to describe where in the specified bucket the job-completion report will be stored. Amazon S3 stores the job-completion report at <code><prefix>
    /// /job-
    /// <job-id>
    /// /report.json
    /// </job-id>
    /// </prefix></code>.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional prefix to describe where in the specified bucket the job-completion report will be stored. Amazon S3 stores the job-completion report at <code><prefix>
    /// /job-
    /// <job-id>
    /// /report.json
    /// </job-id>
    /// </prefix></code>.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>An optional prefix to describe where in the specified bucket the job-completion report will be stored. Amazon S3 stores the job-completion report at <code><prefix>
    /// /job-
    /// <job-id>
    /// /report.json
    /// </job-id>
    /// </prefix></code>.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>Indicates whether the job-completion report will include details of all tasks or only failed tasks.</p>
    pub fn report_scope(mut self, input: crate::types::JobReportScope) -> Self {
        self.report_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the job-completion report will include details of all tasks or only failed tasks.</p>
    pub fn set_report_scope(mut self, input: ::std::option::Option<crate::types::JobReportScope>) -> Self {
        self.report_scope = input;
        self
    }
    /// <p>Indicates whether the job-completion report will include details of all tasks or only failed tasks.</p>
    pub fn get_report_scope(&self) -> &::std::option::Option<crate::types::JobReportScope> {
        &self.report_scope
    }
    /// Consumes the builder and constructs a [`JobReport`](crate::types::JobReport).
    pub fn build(self) -> crate::types::JobReport {
        crate::types::JobReport {
            bucket: self.bucket,
            format: self.format,
            enabled: self.enabled.unwrap_or_default(),
            prefix: self.prefix,
            report_scope: self.report_scope,
        }
    }
}
