// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details that are available for an export.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Export {
    /// <p>The Amazon Resource Name (ARN) for this export.</p>
    pub export_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of this specific data export.</p>
    pub name: ::std::string::String,
    /// <p>The description for this specific data export.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The data query for this specific data export.</p>
    pub data_query: ::std::option::Option<crate::types::DataQuery>,
    /// <p>The destination configuration for this specific data export.</p>
    pub destination_configurations: ::std::option::Option<crate::types::DestinationConfigurations>,
    /// <p>The cadence for Amazon Web Services to update the export in your S3 bucket.</p>
    pub refresh_cadence: ::std::option::Option<crate::types::RefreshCadence>,
}
impl Export {
    /// <p>The Amazon Resource Name (ARN) for this export.</p>
    pub fn export_arn(&self) -> ::std::option::Option<&str> {
        self.export_arn.as_deref()
    }
    /// <p>The name of this specific data export.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description for this specific data export.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The data query for this specific data export.</p>
    pub fn data_query(&self) -> ::std::option::Option<&crate::types::DataQuery> {
        self.data_query.as_ref()
    }
    /// <p>The destination configuration for this specific data export.</p>
    pub fn destination_configurations(&self) -> ::std::option::Option<&crate::types::DestinationConfigurations> {
        self.destination_configurations.as_ref()
    }
    /// <p>The cadence for Amazon Web Services to update the export in your S3 bucket.</p>
    pub fn refresh_cadence(&self) -> ::std::option::Option<&crate::types::RefreshCadence> {
        self.refresh_cadence.as_ref()
    }
}
impl Export {
    /// Creates a new builder-style object to manufacture [`Export`](crate::types::Export).
    pub fn builder() -> crate::types::builders::ExportBuilder {
        crate::types::builders::ExportBuilder::default()
    }
}

/// A builder for [`Export`](crate::types::Export).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportBuilder {
    pub(crate) export_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) data_query: ::std::option::Option<crate::types::DataQuery>,
    pub(crate) destination_configurations: ::std::option::Option<crate::types::DestinationConfigurations>,
    pub(crate) refresh_cadence: ::std::option::Option<crate::types::RefreshCadence>,
}
impl ExportBuilder {
    /// <p>The Amazon Resource Name (ARN) for this export.</p>
    pub fn export_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.export_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for this export.</p>
    pub fn set_export_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.export_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for this export.</p>
    pub fn get_export_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.export_arn
    }
    /// <p>The name of this specific data export.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this specific data export.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of this specific data export.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description for this specific data export.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for this specific data export.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for this specific data export.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The data query for this specific data export.</p>
    /// This field is required.
    pub fn data_query(mut self, input: crate::types::DataQuery) -> Self {
        self.data_query = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data query for this specific data export.</p>
    pub fn set_data_query(mut self, input: ::std::option::Option<crate::types::DataQuery>) -> Self {
        self.data_query = input;
        self
    }
    /// <p>The data query for this specific data export.</p>
    pub fn get_data_query(&self) -> &::std::option::Option<crate::types::DataQuery> {
        &self.data_query
    }
    /// <p>The destination configuration for this specific data export.</p>
    /// This field is required.
    pub fn destination_configurations(mut self, input: crate::types::DestinationConfigurations) -> Self {
        self.destination_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination configuration for this specific data export.</p>
    pub fn set_destination_configurations(mut self, input: ::std::option::Option<crate::types::DestinationConfigurations>) -> Self {
        self.destination_configurations = input;
        self
    }
    /// <p>The destination configuration for this specific data export.</p>
    pub fn get_destination_configurations(&self) -> &::std::option::Option<crate::types::DestinationConfigurations> {
        &self.destination_configurations
    }
    /// <p>The cadence for Amazon Web Services to update the export in your S3 bucket.</p>
    /// This field is required.
    pub fn refresh_cadence(mut self, input: crate::types::RefreshCadence) -> Self {
        self.refresh_cadence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The cadence for Amazon Web Services to update the export in your S3 bucket.</p>
    pub fn set_refresh_cadence(mut self, input: ::std::option::Option<crate::types::RefreshCadence>) -> Self {
        self.refresh_cadence = input;
        self
    }
    /// <p>The cadence for Amazon Web Services to update the export in your S3 bucket.</p>
    pub fn get_refresh_cadence(&self) -> &::std::option::Option<crate::types::RefreshCadence> {
        &self.refresh_cadence
    }
    /// Consumes the builder and constructs a [`Export`](crate::types::Export).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::ExportBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::Export, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Export {
            export_arn: self.export_arn,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Export",
                )
            })?,
            description: self.description,
            data_query: self.data_query,
            destination_configurations: self.destination_configurations,
            refresh_cadence: self.refresh_cadence,
        })
    }
}
