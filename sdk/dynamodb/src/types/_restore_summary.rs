// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details for the restore.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreSummary {
    /// <p>The Amazon Resource Name (ARN) of the backup from which the table was restored.</p>
    pub source_backup_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the source table of the backup that is being restored.</p>
    pub source_table_arn: ::std::option::Option<::std::string::String>,
    /// <p>Point in time or source backup time.</p>
    pub restore_date_time: ::aws_smithy_types::DateTime,
    /// <p>Indicates if a restore is in progress or not.</p>
    pub restore_in_progress: bool,
}
impl RestoreSummary {
    /// <p>The Amazon Resource Name (ARN) of the backup from which the table was restored.</p>
    pub fn source_backup_arn(&self) -> ::std::option::Option<&str> {
        self.source_backup_arn.as_deref()
    }
    /// <p>The ARN of the source table of the backup that is being restored.</p>
    pub fn source_table_arn(&self) -> ::std::option::Option<&str> {
        self.source_table_arn.as_deref()
    }
    /// <p>Point in time or source backup time.</p>
    pub fn restore_date_time(&self) -> &::aws_smithy_types::DateTime {
        &self.restore_date_time
    }
    /// <p>Indicates if a restore is in progress or not.</p>
    pub fn restore_in_progress(&self) -> bool {
        self.restore_in_progress
    }
}
impl RestoreSummary {
    /// Creates a new builder-style object to manufacture [`RestoreSummary`](crate::types::RestoreSummary).
    pub fn builder() -> crate::types::builders::RestoreSummaryBuilder {
        crate::types::builders::RestoreSummaryBuilder::default()
    }
}

/// A builder for [`RestoreSummary`](crate::types::RestoreSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreSummaryBuilder {
    pub(crate) source_backup_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_table_arn: ::std::option::Option<::std::string::String>,
    pub(crate) restore_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) restore_in_progress: ::std::option::Option<bool>,
}
impl RestoreSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the backup from which the table was restored.</p>
    pub fn source_backup_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_backup_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the backup from which the table was restored.</p>
    pub fn set_source_backup_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_backup_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the backup from which the table was restored.</p>
    pub fn get_source_backup_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_backup_arn
    }
    /// <p>The ARN of the source table of the backup that is being restored.</p>
    pub fn source_table_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_table_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the source table of the backup that is being restored.</p>
    pub fn set_source_table_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_table_arn = input;
        self
    }
    /// <p>The ARN of the source table of the backup that is being restored.</p>
    pub fn get_source_table_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_table_arn
    }
    /// <p>Point in time or source backup time.</p>
    /// This field is required.
    pub fn restore_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.restore_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Point in time or source backup time.</p>
    pub fn set_restore_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.restore_date_time = input;
        self
    }
    /// <p>Point in time or source backup time.</p>
    pub fn get_restore_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.restore_date_time
    }
    /// <p>Indicates if a restore is in progress or not.</p>
    /// This field is required.
    pub fn restore_in_progress(mut self, input: bool) -> Self {
        self.restore_in_progress = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if a restore is in progress or not.</p>
    pub fn set_restore_in_progress(mut self, input: ::std::option::Option<bool>) -> Self {
        self.restore_in_progress = input;
        self
    }
    /// <p>Indicates if a restore is in progress or not.</p>
    pub fn get_restore_in_progress(&self) -> &::std::option::Option<bool> {
        &self.restore_in_progress
    }
    /// Consumes the builder and constructs a [`RestoreSummary`](crate::types::RestoreSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`restore_date_time`](crate::types::builders::RestoreSummaryBuilder::restore_date_time)
    /// - [`restore_in_progress`](crate::types::builders::RestoreSummaryBuilder::restore_in_progress)
    pub fn build(self) -> ::std::result::Result<crate::types::RestoreSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RestoreSummary {
            source_backup_arn: self.source_backup_arn,
            source_table_arn: self.source_table_arn,
            restore_date_time: self.restore_date_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "restore_date_time",
                    "restore_date_time was not specified but it is required when building RestoreSummary",
                )
            })?,
            restore_in_progress: self.restore_in_progress.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "restore_in_progress",
                    "restore_in_progress was not specified but it is required when building RestoreSummary",
                )
            })?,
        })
    }
}
