// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOtaTaskConfigurationInput {
    /// <p>The over-the-air (OTA) task configuration id.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetOtaTaskConfigurationInput {
    /// <p>The over-the-air (OTA) task configuration id.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetOtaTaskConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetOtaTaskConfigurationInput`](crate::operation::get_ota_task_configuration::GetOtaTaskConfigurationInput).
    pub fn builder() -> crate::operation::get_ota_task_configuration::builders::GetOtaTaskConfigurationInputBuilder {
        crate::operation::get_ota_task_configuration::builders::GetOtaTaskConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetOtaTaskConfigurationInput`](crate::operation::get_ota_task_configuration::GetOtaTaskConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOtaTaskConfigurationInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetOtaTaskConfigurationInputBuilder {
    /// <p>The over-the-air (OTA) task configuration id.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The over-the-air (OTA) task configuration id.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The over-the-air (OTA) task configuration id.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetOtaTaskConfigurationInput`](crate::operation::get_ota_task_configuration::GetOtaTaskConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_ota_task_configuration::GetOtaTaskConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_ota_task_configuration::GetOtaTaskConfigurationInput { identifier: self.identifier })
    }
}
