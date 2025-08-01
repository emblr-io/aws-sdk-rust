// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIntegrationTablePropertiesOutput {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table to be replicated.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>A structure for the source table configuration.</p>
    pub source_table_config: ::std::option::Option<crate::types::SourceTableConfig>,
    /// <p>A structure for the target table configuration.</p>
    pub target_table_config: ::std::option::Option<crate::types::TargetTableConfig>,
    _request_id: Option<String>,
}
impl GetIntegrationTablePropertiesOutput {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>A structure for the source table configuration.</p>
    pub fn source_table_config(&self) -> ::std::option::Option<&crate::types::SourceTableConfig> {
        self.source_table_config.as_ref()
    }
    /// <p>A structure for the target table configuration.</p>
    pub fn target_table_config(&self) -> ::std::option::Option<&crate::types::TargetTableConfig> {
        self.target_table_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetIntegrationTablePropertiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetIntegrationTablePropertiesOutput {
    /// Creates a new builder-style object to manufacture [`GetIntegrationTablePropertiesOutput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesOutput).
    pub fn builder() -> crate::operation::get_integration_table_properties::builders::GetIntegrationTablePropertiesOutputBuilder {
        crate::operation::get_integration_table_properties::builders::GetIntegrationTablePropertiesOutputBuilder::default()
    }
}

/// A builder for [`GetIntegrationTablePropertiesOutput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIntegrationTablePropertiesOutputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_table_config: ::std::option::Option<crate::types::SourceTableConfig>,
    pub(crate) target_table_config: ::std::option::Option<crate::types::TargetTableConfig>,
    _request_id: Option<String>,
}
impl GetIntegrationTablePropertiesOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target table for which to retrieve integration table properties. Currently, this API only supports retrieving properties for target tables, and the provided ARN should be the ARN of the target table in the Glue Data Catalog. Support for retrieving integration table properties for source connections (using the connection ARN) is not yet implemented and will be added in a future release.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table to be replicated.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>A structure for the source table configuration.</p>
    pub fn source_table_config(mut self, input: crate::types::SourceTableConfig) -> Self {
        self.source_table_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure for the source table configuration.</p>
    pub fn set_source_table_config(mut self, input: ::std::option::Option<crate::types::SourceTableConfig>) -> Self {
        self.source_table_config = input;
        self
    }
    /// <p>A structure for the source table configuration.</p>
    pub fn get_source_table_config(&self) -> &::std::option::Option<crate::types::SourceTableConfig> {
        &self.source_table_config
    }
    /// <p>A structure for the target table configuration.</p>
    pub fn target_table_config(mut self, input: crate::types::TargetTableConfig) -> Self {
        self.target_table_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure for the target table configuration.</p>
    pub fn set_target_table_config(mut self, input: ::std::option::Option<crate::types::TargetTableConfig>) -> Self {
        self.target_table_config = input;
        self
    }
    /// <p>A structure for the target table configuration.</p>
    pub fn get_target_table_config(&self) -> &::std::option::Option<crate::types::TargetTableConfig> {
        &self.target_table_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetIntegrationTablePropertiesOutput`](crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesOutput).
    pub fn build(self) -> crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesOutput {
        crate::operation::get_integration_table_properties::GetIntegrationTablePropertiesOutput {
            resource_arn: self.resource_arn,
            table_name: self.table_name,
            source_table_config: self.source_table_config,
            target_table_config: self.target_table_config,
            _request_id: self._request_id,
        }
    }
}
