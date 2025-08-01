// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIdNamespaceOutput {
    /// <p>The name of the ID namespace.</p>
    pub id_namespace_name: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the ID namespace.</p>
    pub id_namespace_arn: ::std::string::String,
    /// <p>The description of the ID namespace.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>InputSource</code> objects, which have the fields <code>InputSourceARN</code> and <code>SchemaName</code>.</p>
    pub input_source_config: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>>,
    /// <p>Determines the properties of <code>IdMappingWorkflow</code> where this <code>IdNamespace</code> can be used as a <code>Source</code> or a <code>Target</code>.</p>
    pub id_mapping_workflow_properties: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>>,
    /// <p>The type of ID namespace. There are two types: <code>SOURCE</code> and <code>TARGET</code>.</p>
    /// <p>The <code>SOURCE</code> contains configurations for <code>sourceId</code> data that will be processed in an ID mapping workflow.</p>
    /// <p>The <code>TARGET</code> contains a configuration of <code>targetId</code> to which all <code>sourceIds</code> will resolve to.</p>
    pub r#type: crate::types::IdNamespaceType,
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in <code>inputSourceConfig</code> on your behalf as part of the workflow run.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the ID namespace was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The timestamp of when the ID namespace was last updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateIdNamespaceOutput {
    /// <p>The name of the ID namespace.</p>
    pub fn id_namespace_name(&self) -> &str {
        use std::ops::Deref;
        self.id_namespace_name.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the ID namespace.</p>
    pub fn id_namespace_arn(&self) -> &str {
        use std::ops::Deref;
        self.id_namespace_arn.deref()
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
    /// <p>The type of ID namespace. There are two types: <code>SOURCE</code> and <code>TARGET</code>.</p>
    /// <p>The <code>SOURCE</code> contains configurations for <code>sourceId</code> data that will be processed in an ID mapping workflow.</p>
    /// <p>The <code>TARGET</code> contains a configuration of <code>targetId</code> to which all <code>sourceIds</code> will resolve to.</p>
    pub fn r#type(&self) -> &crate::types::IdNamespaceType {
        &self.r#type
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in <code>inputSourceConfig</code> on your behalf as part of the workflow run.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The timestamp of when the ID namespace was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The timestamp of when the ID namespace was last updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateIdNamespaceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateIdNamespaceOutput {
    /// Creates a new builder-style object to manufacture [`CreateIdNamespaceOutput`](crate::operation::create_id_namespace::CreateIdNamespaceOutput).
    pub fn builder() -> crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder {
        crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::default()
    }
}

/// A builder for [`CreateIdNamespaceOutput`](crate::operation::create_id_namespace::CreateIdNamespaceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIdNamespaceOutputBuilder {
    pub(crate) id_namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) id_namespace_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) input_source_config: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceInputSource>>,
    pub(crate) id_mapping_workflow_properties: ::std::option::Option<::std::vec::Vec<crate::types::IdNamespaceIdMappingWorkflowProperties>>,
    pub(crate) r#type: ::std::option::Option<crate::types::IdNamespaceType>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateIdNamespaceOutputBuilder {
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
    /// <p>The Amazon Resource Name (ARN) of the ID namespace.</p>
    /// This field is required.
    pub fn id_namespace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id_namespace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ID namespace.</p>
    pub fn set_id_namespace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id_namespace_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ID namespace.</p>
    pub fn get_id_namespace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.id_namespace_arn
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
    /// <p>The type of ID namespace. There are two types: <code>SOURCE</code> and <code>TARGET</code>.</p>
    /// <p>The <code>SOURCE</code> contains configurations for <code>sourceId</code> data that will be processed in an ID mapping workflow.</p>
    /// <p>The <code>TARGET</code> contains a configuration of <code>targetId</code> to which all <code>sourceIds</code> will resolve to.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::IdNamespaceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of ID namespace. There are two types: <code>SOURCE</code> and <code>TARGET</code>.</p>
    /// <p>The <code>SOURCE</code> contains configurations for <code>sourceId</code> data that will be processed in an ID mapping workflow.</p>
    /// <p>The <code>TARGET</code> contains a configuration of <code>targetId</code> to which all <code>sourceIds</code> will resolve to.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::IdNamespaceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of ID namespace. There are two types: <code>SOURCE</code> and <code>TARGET</code>.</p>
    /// <p>The <code>SOURCE</code> contains configurations for <code>sourceId</code> data that will be processed in an ID mapping workflow.</p>
    /// <p>The <code>TARGET</code> contains a configuration of <code>targetId</code> to which all <code>sourceIds</code> will resolve to.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::IdNamespaceType> {
        &self.r#type
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in <code>inputSourceConfig</code> on your behalf as part of the workflow run.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in <code>inputSourceConfig</code> on your behalf as part of the workflow run.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role. Entity Resolution assumes this role to access the resources defined in <code>inputSourceConfig</code> on your behalf as part of the workflow run.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The timestamp of when the ID namespace was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the ID namespace was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the ID namespace was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp of when the ID namespace was last updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the ID namespace was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp of when the ID namespace was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateIdNamespaceOutput`](crate::operation::create_id_namespace::CreateIdNamespaceOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id_namespace_name`](crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::id_namespace_name)
    /// - [`id_namespace_arn`](crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::id_namespace_arn)
    /// - [`r#type`](crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::type)
    /// - [`created_at`](crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::created_at)
    /// - [`updated_at`](crate::operation::create_id_namespace::builders::CreateIdNamespaceOutputBuilder::updated_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_id_namespace::CreateIdNamespaceOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_id_namespace::CreateIdNamespaceOutput {
            id_namespace_name: self.id_namespace_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id_namespace_name",
                    "id_namespace_name was not specified but it is required when building CreateIdNamespaceOutput",
                )
            })?,
            id_namespace_arn: self.id_namespace_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id_namespace_arn",
                    "id_namespace_arn was not specified but it is required when building CreateIdNamespaceOutput",
                )
            })?,
            description: self.description,
            input_source_config: self.input_source_config,
            id_mapping_workflow_properties: self.id_mapping_workflow_properties,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building CreateIdNamespaceOutput",
                )
            })?,
            role_arn: self.role_arn,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building CreateIdNamespaceOutput",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building CreateIdNamespaceOutput",
                )
            })?,
            tags: self.tags,
            _request_id: self._request_id,
        })
    }
}
