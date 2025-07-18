// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of the data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum DataSourceConfigurationOutput {
    /// <p>The configuration of the Amazon Web Services Glue data source.</p>
    GlueRunConfiguration(crate::types::GlueRunConfigurationOutput),
    /// <p>The configuration of the Amazon Redshift data source.</p>
    RedshiftRunConfiguration(crate::types::RedshiftRunConfigurationOutput),
    /// <p>The Amazon SageMaker run configuration.</p>
    SageMakerRunConfiguration(crate::types::SageMakerRunConfigurationOutput),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl DataSourceConfigurationOutput {
    /// Tries to convert the enum instance into [`GlueRunConfiguration`](crate::types::DataSourceConfigurationOutput::GlueRunConfiguration), extracting the inner [`GlueRunConfigurationOutput`](crate::types::GlueRunConfigurationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_glue_run_configuration(&self) -> ::std::result::Result<&crate::types::GlueRunConfigurationOutput, &Self> {
        if let DataSourceConfigurationOutput::GlueRunConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GlueRunConfiguration`](crate::types::DataSourceConfigurationOutput::GlueRunConfiguration).
    pub fn is_glue_run_configuration(&self) -> bool {
        self.as_glue_run_configuration().is_ok()
    }
    /// Tries to convert the enum instance into [`RedshiftRunConfiguration`](crate::types::DataSourceConfigurationOutput::RedshiftRunConfiguration), extracting the inner [`RedshiftRunConfigurationOutput`](crate::types::RedshiftRunConfigurationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_redshift_run_configuration(&self) -> ::std::result::Result<&crate::types::RedshiftRunConfigurationOutput, &Self> {
        if let DataSourceConfigurationOutput::RedshiftRunConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`RedshiftRunConfiguration`](crate::types::DataSourceConfigurationOutput::RedshiftRunConfiguration).
    pub fn is_redshift_run_configuration(&self) -> bool {
        self.as_redshift_run_configuration().is_ok()
    }
    /// Tries to convert the enum instance into [`SageMakerRunConfiguration`](crate::types::DataSourceConfigurationOutput::SageMakerRunConfiguration), extracting the inner [`SageMakerRunConfigurationOutput`](crate::types::SageMakerRunConfigurationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_sage_maker_run_configuration(&self) -> ::std::result::Result<&crate::types::SageMakerRunConfigurationOutput, &Self> {
        if let DataSourceConfigurationOutput::SageMakerRunConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`SageMakerRunConfiguration`](crate::types::DataSourceConfigurationOutput::SageMakerRunConfiguration).
    pub fn is_sage_maker_run_configuration(&self) -> bool {
        self.as_sage_maker_run_configuration().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
