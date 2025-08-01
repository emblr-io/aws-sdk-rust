// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration parameters for AWS Backint Agent for SAP HANA. You can backup your SAP HANA database with AWS Backup or Amazon S3.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BackintConfig {
    /// <p>AWS service for your database backup.</p>
    pub backint_mode: crate::types::BackintMode,
    /// <p></p>
    pub ensure_no_backup_in_process: bool,
}
impl BackintConfig {
    /// <p>AWS service for your database backup.</p>
    pub fn backint_mode(&self) -> &crate::types::BackintMode {
        &self.backint_mode
    }
    /// <p></p>
    pub fn ensure_no_backup_in_process(&self) -> bool {
        self.ensure_no_backup_in_process
    }
}
impl BackintConfig {
    /// Creates a new builder-style object to manufacture [`BackintConfig`](crate::types::BackintConfig).
    pub fn builder() -> crate::types::builders::BackintConfigBuilder {
        crate::types::builders::BackintConfigBuilder::default()
    }
}

/// A builder for [`BackintConfig`](crate::types::BackintConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BackintConfigBuilder {
    pub(crate) backint_mode: ::std::option::Option<crate::types::BackintMode>,
    pub(crate) ensure_no_backup_in_process: ::std::option::Option<bool>,
}
impl BackintConfigBuilder {
    /// <p>AWS service for your database backup.</p>
    /// This field is required.
    pub fn backint_mode(mut self, input: crate::types::BackintMode) -> Self {
        self.backint_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>AWS service for your database backup.</p>
    pub fn set_backint_mode(mut self, input: ::std::option::Option<crate::types::BackintMode>) -> Self {
        self.backint_mode = input;
        self
    }
    /// <p>AWS service for your database backup.</p>
    pub fn get_backint_mode(&self) -> &::std::option::Option<crate::types::BackintMode> {
        &self.backint_mode
    }
    /// <p></p>
    /// This field is required.
    pub fn ensure_no_backup_in_process(mut self, input: bool) -> Self {
        self.ensure_no_backup_in_process = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_ensure_no_backup_in_process(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ensure_no_backup_in_process = input;
        self
    }
    /// <p></p>
    pub fn get_ensure_no_backup_in_process(&self) -> &::std::option::Option<bool> {
        &self.ensure_no_backup_in_process
    }
    /// Consumes the builder and constructs a [`BackintConfig`](crate::types::BackintConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`backint_mode`](crate::types::builders::BackintConfigBuilder::backint_mode)
    /// - [`ensure_no_backup_in_process`](crate::types::builders::BackintConfigBuilder::ensure_no_backup_in_process)
    pub fn build(self) -> ::std::result::Result<crate::types::BackintConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BackintConfig {
            backint_mode: self.backint_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "backint_mode",
                    "backint_mode was not specified but it is required when building BackintConfig",
                )
            })?,
            ensure_no_backup_in_process: self.ensure_no_backup_in_process.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ensure_no_backup_in_process",
                    "ensure_no_backup_in_process was not specified but it is required when building BackintConfig",
                )
            })?,
        })
    }
}
