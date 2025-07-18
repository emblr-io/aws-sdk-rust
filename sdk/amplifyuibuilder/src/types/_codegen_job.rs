// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the configuration for a code generation job that is associated with an Amplify app.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodegenJob {
    /// <p>The unique ID for the code generation job.</p>
    pub id: ::std::string::String,
    /// <p>The ID of the Amplify app associated with the code generation job.</p>
    pub app_id: ::std::string::String,
    /// <p>The name of the backend environment associated with the code generation job.</p>
    pub environment_name: ::std::string::String,
    /// <p>Describes the configuration information for rendering the UI component associated with the code generation job.</p>
    pub render_config: ::std::option::Option<crate::types::CodegenJobRenderConfig>,
    /// <p>Describes the data schema for a code generation job.</p>
    pub generic_data_schema: ::std::option::Option<crate::types::CodegenJobGenericDataSchema>,
    /// <p>Specifies whether to autogenerate forms in the code generation job.</p>
    pub auto_generate_forms: ::std::option::Option<bool>,
    /// <p>Describes the feature flags that you can specify for a code generation job.</p>
    pub features: ::std::option::Option<crate::types::CodegenFeatureFlags>,
    /// <p>The status of the code generation job.</p>
    pub status: ::std::option::Option<crate::types::CodegenJobStatus>,
    /// <p>The customized status message for the code generation job.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>The <code>CodegenJobAsset</code> to use for the code generation job.</p>
    pub asset: ::std::option::Option<crate::types::CodegenJobAsset>,
    /// <p>One or more key-value pairs to use when tagging the code generation job.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The time that the code generation job was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that the code generation job was modified.</p>
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Lists the dependency packages that may be required for the project code to run.</p>
    pub dependencies: ::std::option::Option<::std::vec::Vec<crate::types::CodegenDependency>>,
}
impl CodegenJob {
    /// <p>The unique ID for the code generation job.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The ID of the Amplify app associated with the code generation job.</p>
    pub fn app_id(&self) -> &str {
        use std::ops::Deref;
        self.app_id.deref()
    }
    /// <p>The name of the backend environment associated with the code generation job.</p>
    pub fn environment_name(&self) -> &str {
        use std::ops::Deref;
        self.environment_name.deref()
    }
    /// <p>Describes the configuration information for rendering the UI component associated with the code generation job.</p>
    pub fn render_config(&self) -> ::std::option::Option<&crate::types::CodegenJobRenderConfig> {
        self.render_config.as_ref()
    }
    /// <p>Describes the data schema for a code generation job.</p>
    pub fn generic_data_schema(&self) -> ::std::option::Option<&crate::types::CodegenJobGenericDataSchema> {
        self.generic_data_schema.as_ref()
    }
    /// <p>Specifies whether to autogenerate forms in the code generation job.</p>
    pub fn auto_generate_forms(&self) -> ::std::option::Option<bool> {
        self.auto_generate_forms
    }
    /// <p>Describes the feature flags that you can specify for a code generation job.</p>
    pub fn features(&self) -> ::std::option::Option<&crate::types::CodegenFeatureFlags> {
        self.features.as_ref()
    }
    /// <p>The status of the code generation job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::CodegenJobStatus> {
        self.status.as_ref()
    }
    /// <p>The customized status message for the code generation job.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>The <code>CodegenJobAsset</code> to use for the code generation job.</p>
    pub fn asset(&self) -> ::std::option::Option<&crate::types::CodegenJobAsset> {
        self.asset.as_ref()
    }
    /// <p>One or more key-value pairs to use when tagging the code generation job.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The time that the code generation job was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The time that the code generation job was modified.</p>
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
    /// <p>Lists the dependency packages that may be required for the project code to run.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dependencies.is_none()`.
    pub fn dependencies(&self) -> &[crate::types::CodegenDependency] {
        self.dependencies.as_deref().unwrap_or_default()
    }
}
impl CodegenJob {
    /// Creates a new builder-style object to manufacture [`CodegenJob`](crate::types::CodegenJob).
    pub fn builder() -> crate::types::builders::CodegenJobBuilder {
        crate::types::builders::CodegenJobBuilder::default()
    }
}

/// A builder for [`CodegenJob`](crate::types::CodegenJob).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodegenJobBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) render_config: ::std::option::Option<crate::types::CodegenJobRenderConfig>,
    pub(crate) generic_data_schema: ::std::option::Option<crate::types::CodegenJobGenericDataSchema>,
    pub(crate) auto_generate_forms: ::std::option::Option<bool>,
    pub(crate) features: ::std::option::Option<crate::types::CodegenFeatureFlags>,
    pub(crate) status: ::std::option::Option<crate::types::CodegenJobStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) asset: ::std::option::Option<crate::types::CodegenJobAsset>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) dependencies: ::std::option::Option<::std::vec::Vec<crate::types::CodegenDependency>>,
}
impl CodegenJobBuilder {
    /// <p>The unique ID for the code generation job.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the code generation job.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID for the code generation job.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ID of the Amplify app associated with the code generation job.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amplify app associated with the code generation job.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The ID of the Amplify app associated with the code generation job.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name of the backend environment associated with the code generation job.</p>
    /// This field is required.
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the backend environment associated with the code generation job.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The name of the backend environment associated with the code generation job.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// <p>Describes the configuration information for rendering the UI component associated with the code generation job.</p>
    pub fn render_config(mut self, input: crate::types::CodegenJobRenderConfig) -> Self {
        self.render_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the configuration information for rendering the UI component associated with the code generation job.</p>
    pub fn set_render_config(mut self, input: ::std::option::Option<crate::types::CodegenJobRenderConfig>) -> Self {
        self.render_config = input;
        self
    }
    /// <p>Describes the configuration information for rendering the UI component associated with the code generation job.</p>
    pub fn get_render_config(&self) -> &::std::option::Option<crate::types::CodegenJobRenderConfig> {
        &self.render_config
    }
    /// <p>Describes the data schema for a code generation job.</p>
    pub fn generic_data_schema(mut self, input: crate::types::CodegenJobGenericDataSchema) -> Self {
        self.generic_data_schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the data schema for a code generation job.</p>
    pub fn set_generic_data_schema(mut self, input: ::std::option::Option<crate::types::CodegenJobGenericDataSchema>) -> Self {
        self.generic_data_schema = input;
        self
    }
    /// <p>Describes the data schema for a code generation job.</p>
    pub fn get_generic_data_schema(&self) -> &::std::option::Option<crate::types::CodegenJobGenericDataSchema> {
        &self.generic_data_schema
    }
    /// <p>Specifies whether to autogenerate forms in the code generation job.</p>
    pub fn auto_generate_forms(mut self, input: bool) -> Self {
        self.auto_generate_forms = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to autogenerate forms in the code generation job.</p>
    pub fn set_auto_generate_forms(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_generate_forms = input;
        self
    }
    /// <p>Specifies whether to autogenerate forms in the code generation job.</p>
    pub fn get_auto_generate_forms(&self) -> &::std::option::Option<bool> {
        &self.auto_generate_forms
    }
    /// <p>Describes the feature flags that you can specify for a code generation job.</p>
    pub fn features(mut self, input: crate::types::CodegenFeatureFlags) -> Self {
        self.features = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the feature flags that you can specify for a code generation job.</p>
    pub fn set_features(mut self, input: ::std::option::Option<crate::types::CodegenFeatureFlags>) -> Self {
        self.features = input;
        self
    }
    /// <p>Describes the feature flags that you can specify for a code generation job.</p>
    pub fn get_features(&self) -> &::std::option::Option<crate::types::CodegenFeatureFlags> {
        &self.features
    }
    /// <p>The status of the code generation job.</p>
    pub fn status(mut self, input: crate::types::CodegenJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the code generation job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CodegenJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the code generation job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CodegenJobStatus> {
        &self.status
    }
    /// <p>The customized status message for the code generation job.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The customized status message for the code generation job.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The customized status message for the code generation job.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>The <code>CodegenJobAsset</code> to use for the code generation job.</p>
    pub fn asset(mut self, input: crate::types::CodegenJobAsset) -> Self {
        self.asset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>CodegenJobAsset</code> to use for the code generation job.</p>
    pub fn set_asset(mut self, input: ::std::option::Option<crate::types::CodegenJobAsset>) -> Self {
        self.asset = input;
        self
    }
    /// <p>The <code>CodegenJobAsset</code> to use for the code generation job.</p>
    pub fn get_asset(&self) -> &::std::option::Option<crate::types::CodegenJobAsset> {
        &self.asset
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>One or more key-value pairs to use when tagging the code generation job.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>One or more key-value pairs to use when tagging the code generation job.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>One or more key-value pairs to use when tagging the code generation job.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The time that the code generation job was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the code generation job was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time that the code generation job was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The time that the code generation job was modified.</p>
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the code generation job was modified.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>The time that the code generation job was modified.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// Appends an item to `dependencies`.
    ///
    /// To override the contents of this collection use [`set_dependencies`](Self::set_dependencies).
    ///
    /// <p>Lists the dependency packages that may be required for the project code to run.</p>
    pub fn dependencies(mut self, input: crate::types::CodegenDependency) -> Self {
        let mut v = self.dependencies.unwrap_or_default();
        v.push(input);
        self.dependencies = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists the dependency packages that may be required for the project code to run.</p>
    pub fn set_dependencies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CodegenDependency>>) -> Self {
        self.dependencies = input;
        self
    }
    /// <p>Lists the dependency packages that may be required for the project code to run.</p>
    pub fn get_dependencies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CodegenDependency>> {
        &self.dependencies
    }
    /// Consumes the builder and constructs a [`CodegenJob`](crate::types::CodegenJob).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::CodegenJobBuilder::id)
    /// - [`app_id`](crate::types::builders::CodegenJobBuilder::app_id)
    /// - [`environment_name`](crate::types::builders::CodegenJobBuilder::environment_name)
    pub fn build(self) -> ::std::result::Result<crate::types::CodegenJob, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CodegenJob {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CodegenJob",
                )
            })?,
            app_id: self.app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_id",
                    "app_id was not specified but it is required when building CodegenJob",
                )
            })?,
            environment_name: self.environment_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "environment_name",
                    "environment_name was not specified but it is required when building CodegenJob",
                )
            })?,
            render_config: self.render_config,
            generic_data_schema: self.generic_data_schema,
            auto_generate_forms: self.auto_generate_forms,
            features: self.features,
            status: self.status,
            status_message: self.status_message,
            asset: self.asset,
            tags: self.tags,
            created_at: self.created_at,
            modified_at: self.modified_at,
            dependencies: self.dependencies,
        })
    }
}
