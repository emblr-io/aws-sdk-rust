// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for data related to the storage class analysis for an Amazon S3 bucket for export.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageClassAnalysisDataExport {
    /// <p>The version of the output schema to use when exporting data. Must be <code>V_1</code>.</p>
    pub output_schema_version: crate::types::StorageClassAnalysisSchemaVersion,
    /// <p>The place to store the data for an analysis.</p>
    pub destination: ::std::option::Option<crate::types::AnalyticsExportDestination>,
}
impl StorageClassAnalysisDataExport {
    /// <p>The version of the output schema to use when exporting data. Must be <code>V_1</code>.</p>
    pub fn output_schema_version(&self) -> &crate::types::StorageClassAnalysisSchemaVersion {
        &self.output_schema_version
    }
    /// <p>The place to store the data for an analysis.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::AnalyticsExportDestination> {
        self.destination.as_ref()
    }
}
impl StorageClassAnalysisDataExport {
    /// Creates a new builder-style object to manufacture [`StorageClassAnalysisDataExport`](crate::types::StorageClassAnalysisDataExport).
    pub fn builder() -> crate::types::builders::StorageClassAnalysisDataExportBuilder {
        crate::types::builders::StorageClassAnalysisDataExportBuilder::default()
    }
}

/// A builder for [`StorageClassAnalysisDataExport`](crate::types::StorageClassAnalysisDataExport).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageClassAnalysisDataExportBuilder {
    pub(crate) output_schema_version: ::std::option::Option<crate::types::StorageClassAnalysisSchemaVersion>,
    pub(crate) destination: ::std::option::Option<crate::types::AnalyticsExportDestination>,
}
impl StorageClassAnalysisDataExportBuilder {
    /// <p>The version of the output schema to use when exporting data. Must be <code>V_1</code>.</p>
    /// This field is required.
    pub fn output_schema_version(mut self, input: crate::types::StorageClassAnalysisSchemaVersion) -> Self {
        self.output_schema_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the output schema to use when exporting data. Must be <code>V_1</code>.</p>
    pub fn set_output_schema_version(mut self, input: ::std::option::Option<crate::types::StorageClassAnalysisSchemaVersion>) -> Self {
        self.output_schema_version = input;
        self
    }
    /// <p>The version of the output schema to use when exporting data. Must be <code>V_1</code>.</p>
    pub fn get_output_schema_version(&self) -> &::std::option::Option<crate::types::StorageClassAnalysisSchemaVersion> {
        &self.output_schema_version
    }
    /// <p>The place to store the data for an analysis.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::AnalyticsExportDestination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The place to store the data for an analysis.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::AnalyticsExportDestination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The place to store the data for an analysis.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::AnalyticsExportDestination> {
        &self.destination
    }
    /// Consumes the builder and constructs a [`StorageClassAnalysisDataExport`](crate::types::StorageClassAnalysisDataExport).
    /// This method will fail if any of the following fields are not set:
    /// - [`output_schema_version`](crate::types::builders::StorageClassAnalysisDataExportBuilder::output_schema_version)
    pub fn build(self) -> ::std::result::Result<crate::types::StorageClassAnalysisDataExport, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StorageClassAnalysisDataExport {
            output_schema_version: self.output_schema_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "output_schema_version",
                    "output_schema_version was not specified but it is required when building StorageClassAnalysisDataExport",
                )
            })?,
            destination: self.destination,
        })
    }
}
