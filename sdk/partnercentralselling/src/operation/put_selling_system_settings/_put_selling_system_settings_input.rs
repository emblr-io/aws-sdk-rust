// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutSellingSystemSettingsInput {
    /// <p>Specifies the catalog in which the settings will be updated. Acceptable values include <code>AWS</code> for production and <code>Sandbox</code> for testing environments.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ARN of the IAM Role used for resource snapshot job executions.</p>
    pub resource_snapshot_job_role_identifier: ::std::option::Option<::std::string::String>,
}
impl PutSellingSystemSettingsInput {
    /// <p>Specifies the catalog in which the settings will be updated. Acceptable values include <code>AWS</code> for production and <code>Sandbox</code> for testing environments.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>Specifies the ARN of the IAM Role used for resource snapshot job executions.</p>
    pub fn resource_snapshot_job_role_identifier(&self) -> ::std::option::Option<&str> {
        self.resource_snapshot_job_role_identifier.as_deref()
    }
}
impl PutSellingSystemSettingsInput {
    /// Creates a new builder-style object to manufacture [`PutSellingSystemSettingsInput`](crate::operation::put_selling_system_settings::PutSellingSystemSettingsInput).
    pub fn builder() -> crate::operation::put_selling_system_settings::builders::PutSellingSystemSettingsInputBuilder {
        crate::operation::put_selling_system_settings::builders::PutSellingSystemSettingsInputBuilder::default()
    }
}

/// A builder for [`PutSellingSystemSettingsInput`](crate::operation::put_selling_system_settings::PutSellingSystemSettingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutSellingSystemSettingsInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) resource_snapshot_job_role_identifier: ::std::option::Option<::std::string::String>,
}
impl PutSellingSystemSettingsInputBuilder {
    /// <p>Specifies the catalog in which the settings will be updated. Acceptable values include <code>AWS</code> for production and <code>Sandbox</code> for testing environments.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog in which the settings will be updated. Acceptable values include <code>AWS</code> for production and <code>Sandbox</code> for testing environments.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog in which the settings will be updated. Acceptable values include <code>AWS</code> for production and <code>Sandbox</code> for testing environments.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>Specifies the ARN of the IAM Role used for resource snapshot job executions.</p>
    pub fn resource_snapshot_job_role_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_snapshot_job_role_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the IAM Role used for resource snapshot job executions.</p>
    pub fn set_resource_snapshot_job_role_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_snapshot_job_role_identifier = input;
        self
    }
    /// <p>Specifies the ARN of the IAM Role used for resource snapshot job executions.</p>
    pub fn get_resource_snapshot_job_role_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_snapshot_job_role_identifier
    }
    /// Consumes the builder and constructs a [`PutSellingSystemSettingsInput`](crate::operation::put_selling_system_settings::PutSellingSystemSettingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_selling_system_settings::PutSellingSystemSettingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_selling_system_settings::PutSellingSystemSettingsInput {
            catalog: self.catalog,
            resource_snapshot_job_role_identifier: self.resource_snapshot_job_role_identifier,
        })
    }
}
