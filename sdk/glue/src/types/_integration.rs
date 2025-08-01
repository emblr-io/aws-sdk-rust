// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a zero-ETL integration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Integration {
    /// <p>The ARN for the source of the integration.</p>
    pub source_arn: ::std::string::String,
    /// <p>The ARN for the target of the integration.</p>
    pub target_arn: ::std::string::String,
    /// <p>A description for the integration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A unique name for the integration.</p>
    pub integration_name: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) for the integration.</p>
    pub integration_arn: ::std::string::String,
    /// <p>The ARN of a KMS key used for encrypting the channel.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>An optional set of non-secret key–value pairs that contains additional contextual information for encryption. This can only be provided if <code>KMSKeyId</code> is provided.</p>
    pub additional_encryption_context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Metadata assigned to the resource consisting of a list of key-value pairs.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The possible statuses are:</p>
    /// <ul>
    /// <li>
    /// <p>CREATING: The integration is being created.</p></li>
    /// <li>
    /// <p>ACTIVE: The integration creation succeeds.</p></li>
    /// <li>
    /// <p>MODIFYING: The integration is being modified.</p></li>
    /// <li>
    /// <p>FAILED: The integration creation fails.</p></li>
    /// <li>
    /// <p>DELETING: The integration is deleted.</p></li>
    /// <li>
    /// <p>SYNCING: The integration is synchronizing.</p></li>
    /// <li>
    /// <p>NEEDS_ATTENTION: The integration needs attention, such as synchronization.</p></li>
    /// </ul>
    pub status: crate::types::IntegrationStatus,
    /// <p>The time that the integration was created, in UTC.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>Properties associated with the integration.</p>
    pub integration_config: ::std::option::Option<crate::types::IntegrationConfig>,
    /// <p>A list of errors associated with the integration.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::IntegrationError>>,
    /// <p>Selects source tables for the integration using Maxwell filter syntax.</p>
    pub data_filter: ::std::option::Option<::std::string::String>,
}
impl Integration {
    /// <p>The ARN for the source of the integration.</p>
    pub fn source_arn(&self) -> &str {
        use std::ops::Deref;
        self.source_arn.deref()
    }
    /// <p>The ARN for the target of the integration.</p>
    pub fn target_arn(&self) -> &str {
        use std::ops::Deref;
        self.target_arn.deref()
    }
    /// <p>A description for the integration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A unique name for the integration.</p>
    pub fn integration_name(&self) -> &str {
        use std::ops::Deref;
        self.integration_name.deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the integration.</p>
    pub fn integration_arn(&self) -> &str {
        use std::ops::Deref;
        self.integration_arn.deref()
    }
    /// <p>The ARN of a KMS key used for encrypting the channel.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>An optional set of non-secret key–value pairs that contains additional contextual information for encryption. This can only be provided if <code>KMSKeyId</code> is provided.</p>
    pub fn additional_encryption_context(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.additional_encryption_context.as_ref()
    }
    /// <p>Metadata assigned to the resource consisting of a list of key-value pairs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The possible statuses are:</p>
    /// <ul>
    /// <li>
    /// <p>CREATING: The integration is being created.</p></li>
    /// <li>
    /// <p>ACTIVE: The integration creation succeeds.</p></li>
    /// <li>
    /// <p>MODIFYING: The integration is being modified.</p></li>
    /// <li>
    /// <p>FAILED: The integration creation fails.</p></li>
    /// <li>
    /// <p>DELETING: The integration is deleted.</p></li>
    /// <li>
    /// <p>SYNCING: The integration is synchronizing.</p></li>
    /// <li>
    /// <p>NEEDS_ATTENTION: The integration needs attention, such as synchronization.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::IntegrationStatus {
        &self.status
    }
    /// <p>The time that the integration was created, in UTC.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>Properties associated with the integration.</p>
    pub fn integration_config(&self) -> ::std::option::Option<&crate::types::IntegrationConfig> {
        self.integration_config.as_ref()
    }
    /// <p>A list of errors associated with the integration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::IntegrationError] {
        self.errors.as_deref().unwrap_or_default()
    }
    /// <p>Selects source tables for the integration using Maxwell filter syntax.</p>
    pub fn data_filter(&self) -> ::std::option::Option<&str> {
        self.data_filter.as_deref()
    }
}
impl Integration {
    /// Creates a new builder-style object to manufacture [`Integration`](crate::types::Integration).
    pub fn builder() -> crate::types::builders::IntegrationBuilder {
        crate::types::builders::IntegrationBuilder::default()
    }
}

/// A builder for [`Integration`](crate::types::Integration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IntegrationBuilder {
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) target_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) integration_name: ::std::option::Option<::std::string::String>,
    pub(crate) integration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) additional_encryption_context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) status: ::std::option::Option<crate::types::IntegrationStatus>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) integration_config: ::std::option::Option<crate::types::IntegrationConfig>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::IntegrationError>>,
    pub(crate) data_filter: ::std::option::Option<::std::string::String>,
}
impl IntegrationBuilder {
    /// <p>The ARN for the source of the integration.</p>
    /// This field is required.
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the source of the integration.</p>
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// <p>The ARN for the source of the integration.</p>
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// <p>The ARN for the target of the integration.</p>
    /// This field is required.
    pub fn target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the target of the integration.</p>
    pub fn set_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_arn = input;
        self
    }
    /// <p>The ARN for the target of the integration.</p>
    pub fn get_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_arn
    }
    /// <p>A description for the integration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the integration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the integration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A unique name for the integration.</p>
    /// This field is required.
    pub fn integration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique name for the integration.</p>
    pub fn set_integration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_name = input;
        self
    }
    /// <p>A unique name for the integration.</p>
    pub fn get_integration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_name
    }
    /// <p>The Amazon Resource Name (ARN) for the integration.</p>
    /// This field is required.
    pub fn integration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the integration.</p>
    pub fn set_integration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the integration.</p>
    pub fn get_integration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_arn
    }
    /// <p>The ARN of a KMS key used for encrypting the channel.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of a KMS key used for encrypting the channel.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The ARN of a KMS key used for encrypting the channel.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Adds a key-value pair to `additional_encryption_context`.
    ///
    /// To override the contents of this collection use [`set_additional_encryption_context`](Self::set_additional_encryption_context).
    ///
    /// <p>An optional set of non-secret key–value pairs that contains additional contextual information for encryption. This can only be provided if <code>KMSKeyId</code> is provided.</p>
    pub fn additional_encryption_context(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.additional_encryption_context.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.additional_encryption_context = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>An optional set of non-secret key–value pairs that contains additional contextual information for encryption. This can only be provided if <code>KMSKeyId</code> is provided.</p>
    pub fn set_additional_encryption_context(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.additional_encryption_context = input;
        self
    }
    /// <p>An optional set of non-secret key–value pairs that contains additional contextual information for encryption. This can only be provided if <code>KMSKeyId</code> is provided.</p>
    pub fn get_additional_encryption_context(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.additional_encryption_context
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata assigned to the resource consisting of a list of key-value pairs.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata assigned to the resource consisting of a list of key-value pairs.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata assigned to the resource consisting of a list of key-value pairs.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The possible statuses are:</p>
    /// <ul>
    /// <li>
    /// <p>CREATING: The integration is being created.</p></li>
    /// <li>
    /// <p>ACTIVE: The integration creation succeeds.</p></li>
    /// <li>
    /// <p>MODIFYING: The integration is being modified.</p></li>
    /// <li>
    /// <p>FAILED: The integration creation fails.</p></li>
    /// <li>
    /// <p>DELETING: The integration is deleted.</p></li>
    /// <li>
    /// <p>SYNCING: The integration is synchronizing.</p></li>
    /// <li>
    /// <p>NEEDS_ATTENTION: The integration needs attention, such as synchronization.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::IntegrationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The possible statuses are:</p>
    /// <ul>
    /// <li>
    /// <p>CREATING: The integration is being created.</p></li>
    /// <li>
    /// <p>ACTIVE: The integration creation succeeds.</p></li>
    /// <li>
    /// <p>MODIFYING: The integration is being modified.</p></li>
    /// <li>
    /// <p>FAILED: The integration creation fails.</p></li>
    /// <li>
    /// <p>DELETING: The integration is deleted.</p></li>
    /// <li>
    /// <p>SYNCING: The integration is synchronizing.</p></li>
    /// <li>
    /// <p>NEEDS_ATTENTION: The integration needs attention, such as synchronization.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::IntegrationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The possible statuses are:</p>
    /// <ul>
    /// <li>
    /// <p>CREATING: The integration is being created.</p></li>
    /// <li>
    /// <p>ACTIVE: The integration creation succeeds.</p></li>
    /// <li>
    /// <p>MODIFYING: The integration is being modified.</p></li>
    /// <li>
    /// <p>FAILED: The integration creation fails.</p></li>
    /// <li>
    /// <p>DELETING: The integration is deleted.</p></li>
    /// <li>
    /// <p>SYNCING: The integration is synchronizing.</p></li>
    /// <li>
    /// <p>NEEDS_ATTENTION: The integration needs attention, such as synchronization.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::IntegrationStatus> {
        &self.status
    }
    /// <p>The time that the integration was created, in UTC.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the integration was created, in UTC.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time that the integration was created, in UTC.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>Properties associated with the integration.</p>
    pub fn integration_config(mut self, input: crate::types::IntegrationConfig) -> Self {
        self.integration_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Properties associated with the integration.</p>
    pub fn set_integration_config(mut self, input: ::std::option::Option<crate::types::IntegrationConfig>) -> Self {
        self.integration_config = input;
        self
    }
    /// <p>Properties associated with the integration.</p>
    pub fn get_integration_config(&self) -> &::std::option::Option<crate::types::IntegrationConfig> {
        &self.integration_config
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>A list of errors associated with the integration.</p>
    pub fn errors(mut self, input: crate::types::IntegrationError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of errors associated with the integration.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IntegrationError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>A list of errors associated with the integration.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IntegrationError>> {
        &self.errors
    }
    /// <p>Selects source tables for the integration using Maxwell filter syntax.</p>
    pub fn data_filter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_filter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Selects source tables for the integration using Maxwell filter syntax.</p>
    pub fn set_data_filter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_filter = input;
        self
    }
    /// <p>Selects source tables for the integration using Maxwell filter syntax.</p>
    pub fn get_data_filter(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_filter
    }
    /// Consumes the builder and constructs a [`Integration`](crate::types::Integration).
    /// This method will fail if any of the following fields are not set:
    /// - [`source_arn`](crate::types::builders::IntegrationBuilder::source_arn)
    /// - [`target_arn`](crate::types::builders::IntegrationBuilder::target_arn)
    /// - [`integration_name`](crate::types::builders::IntegrationBuilder::integration_name)
    /// - [`integration_arn`](crate::types::builders::IntegrationBuilder::integration_arn)
    /// - [`status`](crate::types::builders::IntegrationBuilder::status)
    /// - [`create_time`](crate::types::builders::IntegrationBuilder::create_time)
    pub fn build(self) -> ::std::result::Result<crate::types::Integration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Integration {
            source_arn: self.source_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_arn",
                    "source_arn was not specified but it is required when building Integration",
                )
            })?,
            target_arn: self.target_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "target_arn",
                    "target_arn was not specified but it is required when building Integration",
                )
            })?,
            description: self.description,
            integration_name: self.integration_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "integration_name",
                    "integration_name was not specified but it is required when building Integration",
                )
            })?,
            integration_arn: self.integration_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "integration_arn",
                    "integration_arn was not specified but it is required when building Integration",
                )
            })?,
            kms_key_id: self.kms_key_id,
            additional_encryption_context: self.additional_encryption_context,
            tags: self.tags,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building Integration",
                )
            })?,
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building Integration",
                )
            })?,
            integration_config: self.integration_config,
            errors: self.errors,
            data_filter: self.data_filter,
        })
    }
}
