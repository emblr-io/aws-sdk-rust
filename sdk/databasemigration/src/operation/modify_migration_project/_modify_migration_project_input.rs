// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyMigrationProjectInput {
    /// <p>The identifier of the migration project. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.</p>
    pub migration_project_identifier: ::std::option::Option<::std::string::String>,
    /// <p>A user-friendly name for the migration project.</p>
    pub migration_project_name: ::std::option::Option<::std::string::String>,
    /// <p>Information about the source data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub source_data_provider_descriptors: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    /// <p>Information about the target data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub target_data_provider_descriptors: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    /// <p>The name or Amazon Resource Name (ARN) for the instance profile.</p>
    pub instance_profile_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The settings in JSON format for migration rules. Migration rules make it possible for you to change the object names according to the rules that you specify. For example, you can change an object name to lowercase or uppercase, add or remove a prefix or suffix, or rename objects.</p>
    pub transformation_rules: ::std::option::Option<::std::string::String>,
    /// <p>A user-friendly description of the migration project.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The schema conversion application attributes, including the Amazon S3 bucket name and Amazon S3 role ARN.</p>
    pub schema_conversion_application_attributes: ::std::option::Option<crate::types::ScApplicationAttributes>,
}
impl ModifyMigrationProjectInput {
    /// <p>The identifier of the migration project. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.</p>
    pub fn migration_project_identifier(&self) -> ::std::option::Option<&str> {
        self.migration_project_identifier.as_deref()
    }
    /// <p>A user-friendly name for the migration project.</p>
    pub fn migration_project_name(&self) -> ::std::option::Option<&str> {
        self.migration_project_name.as_deref()
    }
    /// <p>Information about the source data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.source_data_provider_descriptors.is_none()`.
    pub fn source_data_provider_descriptors(&self) -> &[crate::types::DataProviderDescriptorDefinition] {
        self.source_data_provider_descriptors.as_deref().unwrap_or_default()
    }
    /// <p>Information about the target data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_data_provider_descriptors.is_none()`.
    pub fn target_data_provider_descriptors(&self) -> &[crate::types::DataProviderDescriptorDefinition] {
        self.target_data_provider_descriptors.as_deref().unwrap_or_default()
    }
    /// <p>The name or Amazon Resource Name (ARN) for the instance profile.</p>
    pub fn instance_profile_identifier(&self) -> ::std::option::Option<&str> {
        self.instance_profile_identifier.as_deref()
    }
    /// <p>The settings in JSON format for migration rules. Migration rules make it possible for you to change the object names according to the rules that you specify. For example, you can change an object name to lowercase or uppercase, add or remove a prefix or suffix, or rename objects.</p>
    pub fn transformation_rules(&self) -> ::std::option::Option<&str> {
        self.transformation_rules.as_deref()
    }
    /// <p>A user-friendly description of the migration project.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The schema conversion application attributes, including the Amazon S3 bucket name and Amazon S3 role ARN.</p>
    pub fn schema_conversion_application_attributes(&self) -> ::std::option::Option<&crate::types::ScApplicationAttributes> {
        self.schema_conversion_application_attributes.as_ref()
    }
}
impl ModifyMigrationProjectInput {
    /// Creates a new builder-style object to manufacture [`ModifyMigrationProjectInput`](crate::operation::modify_migration_project::ModifyMigrationProjectInput).
    pub fn builder() -> crate::operation::modify_migration_project::builders::ModifyMigrationProjectInputBuilder {
        crate::operation::modify_migration_project::builders::ModifyMigrationProjectInputBuilder::default()
    }
}

/// A builder for [`ModifyMigrationProjectInput`](crate::operation::modify_migration_project::ModifyMigrationProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyMigrationProjectInputBuilder {
    pub(crate) migration_project_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) migration_project_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_data_provider_descriptors: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    pub(crate) target_data_provider_descriptors: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    pub(crate) instance_profile_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) transformation_rules: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) schema_conversion_application_attributes: ::std::option::Option<crate::types::ScApplicationAttributes>,
}
impl ModifyMigrationProjectInputBuilder {
    /// <p>The identifier of the migration project. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.</p>
    /// This field is required.
    pub fn migration_project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.migration_project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the migration project. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.</p>
    pub fn set_migration_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.migration_project_identifier = input;
        self
    }
    /// <p>The identifier of the migration project. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.</p>
    pub fn get_migration_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.migration_project_identifier
    }
    /// <p>A user-friendly name for the migration project.</p>
    pub fn migration_project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.migration_project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-friendly name for the migration project.</p>
    pub fn set_migration_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.migration_project_name = input;
        self
    }
    /// <p>A user-friendly name for the migration project.</p>
    pub fn get_migration_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.migration_project_name
    }
    /// Appends an item to `source_data_provider_descriptors`.
    ///
    /// To override the contents of this collection use [`set_source_data_provider_descriptors`](Self::set_source_data_provider_descriptors).
    ///
    /// <p>Information about the source data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn source_data_provider_descriptors(mut self, input: crate::types::DataProviderDescriptorDefinition) -> Self {
        let mut v = self.source_data_provider_descriptors.unwrap_or_default();
        v.push(input);
        self.source_data_provider_descriptors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the source data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn set_source_data_provider_descriptors(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    ) -> Self {
        self.source_data_provider_descriptors = input;
        self
    }
    /// <p>Information about the source data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn get_source_data_provider_descriptors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>> {
        &self.source_data_provider_descriptors
    }
    /// Appends an item to `target_data_provider_descriptors`.
    ///
    /// To override the contents of this collection use [`set_target_data_provider_descriptors`](Self::set_target_data_provider_descriptors).
    ///
    /// <p>Information about the target data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn target_data_provider_descriptors(mut self, input: crate::types::DataProviderDescriptorDefinition) -> Self {
        let mut v = self.target_data_provider_descriptors.unwrap_or_default();
        v.push(input);
        self.target_data_provider_descriptors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the target data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn set_target_data_provider_descriptors(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>>,
    ) -> Self {
        self.target_data_provider_descriptors = input;
        self
    }
    /// <p>Information about the target data provider, including the name, ARN, and Amazon Web Services Secrets Manager parameters.</p>
    pub fn get_target_data_provider_descriptors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataProviderDescriptorDefinition>> {
        &self.target_data_provider_descriptors
    }
    /// <p>The name or Amazon Resource Name (ARN) for the instance profile.</p>
    pub fn instance_profile_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_profile_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) for the instance profile.</p>
    pub fn set_instance_profile_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_profile_identifier = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) for the instance profile.</p>
    pub fn get_instance_profile_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_profile_identifier
    }
    /// <p>The settings in JSON format for migration rules. Migration rules make it possible for you to change the object names according to the rules that you specify. For example, you can change an object name to lowercase or uppercase, add or remove a prefix or suffix, or rename objects.</p>
    pub fn transformation_rules(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transformation_rules = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The settings in JSON format for migration rules. Migration rules make it possible for you to change the object names according to the rules that you specify. For example, you can change an object name to lowercase or uppercase, add or remove a prefix or suffix, or rename objects.</p>
    pub fn set_transformation_rules(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transformation_rules = input;
        self
    }
    /// <p>The settings in JSON format for migration rules. Migration rules make it possible for you to change the object names according to the rules that you specify. For example, you can change an object name to lowercase or uppercase, add or remove a prefix or suffix, or rename objects.</p>
    pub fn get_transformation_rules(&self) -> &::std::option::Option<::std::string::String> {
        &self.transformation_rules
    }
    /// <p>A user-friendly description of the migration project.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-friendly description of the migration project.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A user-friendly description of the migration project.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The schema conversion application attributes, including the Amazon S3 bucket name and Amazon S3 role ARN.</p>
    pub fn schema_conversion_application_attributes(mut self, input: crate::types::ScApplicationAttributes) -> Self {
        self.schema_conversion_application_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schema conversion application attributes, including the Amazon S3 bucket name and Amazon S3 role ARN.</p>
    pub fn set_schema_conversion_application_attributes(mut self, input: ::std::option::Option<crate::types::ScApplicationAttributes>) -> Self {
        self.schema_conversion_application_attributes = input;
        self
    }
    /// <p>The schema conversion application attributes, including the Amazon S3 bucket name and Amazon S3 role ARN.</p>
    pub fn get_schema_conversion_application_attributes(&self) -> &::std::option::Option<crate::types::ScApplicationAttributes> {
        &self.schema_conversion_application_attributes
    }
    /// Consumes the builder and constructs a [`ModifyMigrationProjectInput`](crate::operation::modify_migration_project::ModifyMigrationProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_migration_project::ModifyMigrationProjectInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_migration_project::ModifyMigrationProjectInput {
            migration_project_identifier: self.migration_project_identifier,
            migration_project_name: self.migration_project_name,
            source_data_provider_descriptors: self.source_data_provider_descriptors,
            target_data_provider_descriptors: self.target_data_provider_descriptors,
            instance_profile_identifier: self.instance_profile_identifier,
            transformation_rules: self.transformation_rules,
            description: self.description,
            schema_conversion_application_attributes: self.schema_conversion_application_attributes,
        })
    }
}
