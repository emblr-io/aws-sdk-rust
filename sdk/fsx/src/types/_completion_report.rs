// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides a report detailing the data repository task results of the files processed that match the criteria specified in the report <code>Scope</code> parameter. FSx delivers the report to the file system's linked data repository in Amazon S3, using the path specified in the report <code>Path</code> parameter. You can specify whether or not a report gets generated for a task using the <code>Enabled</code> parameter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CompletionReport {
    /// <p>Set <code>Enabled</code> to <code>True</code> to generate a <code>CompletionReport</code> when the task completes. If set to <code>true</code>, then you need to provide a report <code>Scope</code>, <code>Path</code>, and <code>Format</code>. Set <code>Enabled</code> to <code>False</code> if you do not want a <code>CompletionReport</code> generated when the task completes.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the location of the report on the file system's linked S3 data repository. An absolute path that defines where the completion report will be stored in the destination location. The <code>Path</code> you provide must be located within the file system’s ExportPath. An example <code>Path</code> value is "s3://amzn-s3-demo-bucket/myExportPath/optionalPrefix". The report provides the following information for each file in the report: FilePath, FileStatus, and ErrorCode.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the format of the <code>CompletionReport</code>. <code>REPORT_CSV_20191124</code> is the only format currently supported. When <code>Format</code> is set to <code>REPORT_CSV_20191124</code>, the <code>CompletionReport</code> is provided in CSV format, and is delivered to <code>{path}/task-{id}/failures.csv</code>.</p>
    pub format: ::std::option::Option<crate::types::ReportFormat>,
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the scope of the <code>CompletionReport</code>; <code>FAILED_FILES_ONLY</code> is the only scope currently supported. When <code>Scope</code> is set to <code>FAILED_FILES_ONLY</code>, the <code>CompletionReport</code> only contains information about files that the data repository task failed to process.</p>
    pub scope: ::std::option::Option<crate::types::ReportScope>,
}
impl CompletionReport {
    /// <p>Set <code>Enabled</code> to <code>True</code> to generate a <code>CompletionReport</code> when the task completes. If set to <code>true</code>, then you need to provide a report <code>Scope</code>, <code>Path</code>, and <code>Format</code>. Set <code>Enabled</code> to <code>False</code> if you do not want a <code>CompletionReport</code> generated when the task completes.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the location of the report on the file system's linked S3 data repository. An absolute path that defines where the completion report will be stored in the destination location. The <code>Path</code> you provide must be located within the file system’s ExportPath. An example <code>Path</code> value is "s3://amzn-s3-demo-bucket/myExportPath/optionalPrefix". The report provides the following information for each file in the report: FilePath, FileStatus, and ErrorCode.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the format of the <code>CompletionReport</code>. <code>REPORT_CSV_20191124</code> is the only format currently supported. When <code>Format</code> is set to <code>REPORT_CSV_20191124</code>, the <code>CompletionReport</code> is provided in CSV format, and is delivered to <code>{path}/task-{id}/failures.csv</code>.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::ReportFormat> {
        self.format.as_ref()
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the scope of the <code>CompletionReport</code>; <code>FAILED_FILES_ONLY</code> is the only scope currently supported. When <code>Scope</code> is set to <code>FAILED_FILES_ONLY</code>, the <code>CompletionReport</code> only contains information about files that the data repository task failed to process.</p>
    pub fn scope(&self) -> ::std::option::Option<&crate::types::ReportScope> {
        self.scope.as_ref()
    }
}
impl CompletionReport {
    /// Creates a new builder-style object to manufacture [`CompletionReport`](crate::types::CompletionReport).
    pub fn builder() -> crate::types::builders::CompletionReportBuilder {
        crate::types::builders::CompletionReportBuilder::default()
    }
}

/// A builder for [`CompletionReport`](crate::types::CompletionReport).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CompletionReportBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) format: ::std::option::Option<crate::types::ReportFormat>,
    pub(crate) scope: ::std::option::Option<crate::types::ReportScope>,
}
impl CompletionReportBuilder {
    /// <p>Set <code>Enabled</code> to <code>True</code> to generate a <code>CompletionReport</code> when the task completes. If set to <code>true</code>, then you need to provide a report <code>Scope</code>, <code>Path</code>, and <code>Format</code>. Set <code>Enabled</code> to <code>False</code> if you do not want a <code>CompletionReport</code> generated when the task completes.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set <code>Enabled</code> to <code>True</code> to generate a <code>CompletionReport</code> when the task completes. If set to <code>true</code>, then you need to provide a report <code>Scope</code>, <code>Path</code>, and <code>Format</code>. Set <code>Enabled</code> to <code>False</code> if you do not want a <code>CompletionReport</code> generated when the task completes.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Set <code>Enabled</code> to <code>True</code> to generate a <code>CompletionReport</code> when the task completes. If set to <code>true</code>, then you need to provide a report <code>Scope</code>, <code>Path</code>, and <code>Format</code>. Set <code>Enabled</code> to <code>False</code> if you do not want a <code>CompletionReport</code> generated when the task completes.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the location of the report on the file system's linked S3 data repository. An absolute path that defines where the completion report will be stored in the destination location. The <code>Path</code> you provide must be located within the file system’s ExportPath. An example <code>Path</code> value is "s3://amzn-s3-demo-bucket/myExportPath/optionalPrefix". The report provides the following information for each file in the report: FilePath, FileStatus, and ErrorCode.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the location of the report on the file system's linked S3 data repository. An absolute path that defines where the completion report will be stored in the destination location. The <code>Path</code> you provide must be located within the file system’s ExportPath. An example <code>Path</code> value is "s3://amzn-s3-demo-bucket/myExportPath/optionalPrefix". The report provides the following information for each file in the report: FilePath, FileStatus, and ErrorCode.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the location of the report on the file system's linked S3 data repository. An absolute path that defines where the completion report will be stored in the destination location. The <code>Path</code> you provide must be located within the file system’s ExportPath. An example <code>Path</code> value is "s3://amzn-s3-demo-bucket/myExportPath/optionalPrefix". The report provides the following information for each file in the report: FilePath, FileStatus, and ErrorCode.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the format of the <code>CompletionReport</code>. <code>REPORT_CSV_20191124</code> is the only format currently supported. When <code>Format</code> is set to <code>REPORT_CSV_20191124</code>, the <code>CompletionReport</code> is provided in CSV format, and is delivered to <code>{path}/task-{id}/failures.csv</code>.</p>
    pub fn format(mut self, input: crate::types::ReportFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the format of the <code>CompletionReport</code>. <code>REPORT_CSV_20191124</code> is the only format currently supported. When <code>Format</code> is set to <code>REPORT_CSV_20191124</code>, the <code>CompletionReport</code> is provided in CSV format, and is delivered to <code>{path}/task-{id}/failures.csv</code>.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::ReportFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the format of the <code>CompletionReport</code>. <code>REPORT_CSV_20191124</code> is the only format currently supported. When <code>Format</code> is set to <code>REPORT_CSV_20191124</code>, the <code>CompletionReport</code> is provided in CSV format, and is delivered to <code>{path}/task-{id}/failures.csv</code>.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::ReportFormat> {
        &self.format
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the scope of the <code>CompletionReport</code>; <code>FAILED_FILES_ONLY</code> is the only scope currently supported. When <code>Scope</code> is set to <code>FAILED_FILES_ONLY</code>, the <code>CompletionReport</code> only contains information about files that the data repository task failed to process.</p>
    pub fn scope(mut self, input: crate::types::ReportScope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the scope of the <code>CompletionReport</code>; <code>FAILED_FILES_ONLY</code> is the only scope currently supported. When <code>Scope</code> is set to <code>FAILED_FILES_ONLY</code>, the <code>CompletionReport</code> only contains information about files that the data repository task failed to process.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::ReportScope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Required if <code>Enabled</code> is set to <code>true</code>. Specifies the scope of the <code>CompletionReport</code>; <code>FAILED_FILES_ONLY</code> is the only scope currently supported. When <code>Scope</code> is set to <code>FAILED_FILES_ONLY</code>, the <code>CompletionReport</code> only contains information about files that the data repository task failed to process.</p>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::ReportScope> {
        &self.scope
    }
    /// Consumes the builder and constructs a [`CompletionReport`](crate::types::CompletionReport).
    pub fn build(self) -> crate::types::CompletionReport {
        crate::types::CompletionReport {
            enabled: self.enabled,
            path: self.path,
            format: self.format,
            scope: self.scope,
        }
    }
}
