// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReplicationConfigurationTemplateInput {
    /// <p>The ID of the Replication Configuration Template to be deleted.</p>
    pub replication_configuration_template_id: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationConfigurationTemplateInput {
    /// <p>The ID of the Replication Configuration Template to be deleted.</p>
    pub fn replication_configuration_template_id(&self) -> ::std::option::Option<&str> {
        self.replication_configuration_template_id.as_deref()
    }
}
impl DeleteReplicationConfigurationTemplateInput {
    /// Creates a new builder-style object to manufacture [`DeleteReplicationConfigurationTemplateInput`](crate::operation::delete_replication_configuration_template::DeleteReplicationConfigurationTemplateInput).
    pub fn builder() -> crate::operation::delete_replication_configuration_template::builders::DeleteReplicationConfigurationTemplateInputBuilder {
        crate::operation::delete_replication_configuration_template::builders::DeleteReplicationConfigurationTemplateInputBuilder::default()
    }
}

/// A builder for [`DeleteReplicationConfigurationTemplateInput`](crate::operation::delete_replication_configuration_template::DeleteReplicationConfigurationTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReplicationConfigurationTemplateInputBuilder {
    pub(crate) replication_configuration_template_id: ::std::option::Option<::std::string::String>,
}
impl DeleteReplicationConfigurationTemplateInputBuilder {
    /// <p>The ID of the Replication Configuration Template to be deleted.</p>
    /// This field is required.
    pub fn replication_configuration_template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_configuration_template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Replication Configuration Template to be deleted.</p>
    pub fn set_replication_configuration_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_configuration_template_id = input;
        self
    }
    /// <p>The ID of the Replication Configuration Template to be deleted.</p>
    pub fn get_replication_configuration_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_configuration_template_id
    }
    /// Consumes the builder and constructs a [`DeleteReplicationConfigurationTemplateInput`](crate::operation::delete_replication_configuration_template::DeleteReplicationConfigurationTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_replication_configuration_template::DeleteReplicationConfigurationTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_replication_configuration_template::DeleteReplicationConfigurationTemplateInput {
                replication_configuration_template_id: self.replication_configuration_template_id,
            },
        )
    }
}
