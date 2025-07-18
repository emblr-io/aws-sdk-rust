// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateIdNamespaceInput {
    /// <p>The name of the ID namespace.</p>
    pub id_namespace_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the ID namespace.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    pub input_source_config: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>>,
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    pub id_mapping_workflow_properties: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in this <code>IdNamespace</code> on your behalf as part of a workflow run.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateIdNamespaceInput {
    /// <p>The name of the ID namespace.</p>
    pub fn id_namespace_name(&self) -> ::std::option::Option<&str> {
        self.id_namespace_name.as_deref()
    }
    /// <p>The description of the ID namespace.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.input_source_config.is_none()`.
    pub fn input_source_config(&self) -> &[crate::types::IdNamespaceInputSource] {
        self.input_source_config.as_deref().unwrap_or_default()
    }
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.id_mapping_workflow_properties.is_none()`.
    pub fn id_mapping_workflow_properties(&self) -> &[crate::types::IdNamespaceIdMappingWorkflowProperties] {
        self.id_mapping_workflow_properties.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in this <code>IdNamespace</code> on your behalf as part of a workflow run.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl UpdateIdNamespaceInput {
    /// Creates a new builder-style object to manufacture [`UpdateIdNamespaceInput`](crate::operation::update_id_namespace::UpdateIdNamespaceInput).
    pub fn builder() -> crate::operation::update_id_namespace::builders::UpdateIdNamespaceInputBuilder {
        crate::operation::update_id_namespace::builders::UpdateIdNamespaceInputBuilder::default()
    }
}

/// A builder for [`UpdateIdNamespaceInput`](crate::operation::update_id_namespace::UpdateIdNamespaceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateIdNamespaceInputBuilder {
    pub(crate) id_namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) input_source_config: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>>,
    pub(crate) id_mapping_workflow_properties: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateIdNamespaceInputBuilder {
    /// <p>The name of the ID namespace.</p>
    /// This field is required.
    pub fn id_namespace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id_namespace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ID namespace.</p>
    pub fn set_id_namespace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id_namespace_name = input;
        self
    }
    /// <p>The name of the ID namespace.</p>
    pub fn get_id_namespace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.id_namespace_name
    }
    /// <p>The description of the ID namespace.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the ID namespace.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the ID namespace.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `input_source_config`.
    ///
    /// To override the contents of this collection use [`set_input_source_config`](Self::set_input_source_config).
    ///
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    pub fn input_source_config(mut self, input: crate::types::IdNamespaceInputSource) -> Self {
        let mut v = self.input_source_config.unwrap_or_default();
        v.push(input);
        self.input_source_config = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    pub fn set_input_source_config(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>>) -> Self {
        self.input_source_config = input;
        self
    }
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    pub fn get_input_source_config(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>> {
        &self.input_source_config
    }
    /// Appends an item to `id_mapping_workflow_properties`.
    ///
    /// To override the contents of this collection use [`set_id_mapping_workflow_properties`](Self::set_id_mapping_workflow_properties).
    ///
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    pub fn id_mapping_workflow_properties(mut self, input: crate::types::IdNamespaceIdMappingWorkflowProperties) -> Self {
        let mut v = self.id_mapping_workflow_properties.unwrap_or_default();
        v.push(input);
        self.id_mapping_workflow_properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    pub fn set_id_mapping_workflow_properties(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>>,
    ) -> Self {
        self.id_mapping_workflow_properties = input;
        self
    }
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    pub fn get_id_mapping_workflow_properties(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>> {
        &self.id_mapping_workflow_properties
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in this <code>IdNamespace</code> on your behalf as part of a workflow run.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in this <code>IdNamespace</code> on your behalf as part of a workflow run.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in this <code>IdNamespace</code> on your behalf as part of a workflow run.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`UpdateIdNamespaceInput`](crate::operation::update_id_namespace::UpdateIdNamespaceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_id_namespace::UpdateIdNamespaceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_id_namespace::UpdateIdNamespaceInput {
            id_namespace_name: self.id_namespace_name,
            description: self.description,
            input_source_config: self.input_source_config,
            id_mapping_workflow_properties: self.id_mapping_workflow_properties,
            role_arn: self.role_arn,
        })
    }
}
