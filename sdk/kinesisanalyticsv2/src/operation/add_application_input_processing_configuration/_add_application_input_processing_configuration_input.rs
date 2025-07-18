// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddApplicationInputProcessingConfigurationInput {
    /// <p>The name of the application to which you want to add the input processing configuration.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the application to which you want to add the input processing configuration. You can use the <code>DescribeApplication</code> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub current_application_version_id: ::std::option::Option<i64>,
    /// <p>The ID of the input configuration to add the input processing configuration to. You can get a list of the input IDs for an application using the <code>DescribeApplication</code> operation.</p>
    pub input_id: ::std::option::Option<::std::string::String>,
    /// <p>The <code>InputProcessingConfiguration</code> to add to the application.</p>
    pub input_processing_configuration: ::std::option::Option<crate::types::InputProcessingConfiguration>,
}
impl AddApplicationInputProcessingConfigurationInput {
    /// <p>The name of the application to which you want to add the input processing configuration.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>The version of the application to which you want to add the input processing configuration. You can use the <code>DescribeApplication</code> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn current_application_version_id(&self) -> ::std::option::Option<i64> {
        self.current_application_version_id
    }
    /// <p>The ID of the input configuration to add the input processing configuration to. You can get a list of the input IDs for an application using the <code>DescribeApplication</code> operation.</p>
    pub fn input_id(&self) -> ::std::option::Option<&str> {
        self.input_id.as_deref()
    }
    /// <p>The <code>InputProcessingConfiguration</code> to add to the application.</p>
    pub fn input_processing_configuration(&self) -> ::std::option::Option<&crate::types::InputProcessingConfiguration> {
        self.input_processing_configuration.as_ref()
    }
}
impl AddApplicationInputProcessingConfigurationInput {
    /// Creates a new builder-style object to manufacture [`AddApplicationInputProcessingConfigurationInput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationInput).
    pub fn builder(
    ) -> crate::operation::add_application_input_processing_configuration::builders::AddApplicationInputProcessingConfigurationInputBuilder {
        crate::operation::add_application_input_processing_configuration::builders::AddApplicationInputProcessingConfigurationInputBuilder::default()
    }
}

/// A builder for [`AddApplicationInputProcessingConfigurationInput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddApplicationInputProcessingConfigurationInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) current_application_version_id: ::std::option::Option<i64>,
    pub(crate) input_id: ::std::option::Option<::std::string::String>,
    pub(crate) input_processing_configuration: ::std::option::Option<crate::types::InputProcessingConfiguration>,
}
impl AddApplicationInputProcessingConfigurationInputBuilder {
    /// <p>The name of the application to which you want to add the input processing configuration.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application to which you want to add the input processing configuration.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>The name of the application to which you want to add the input processing configuration.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>The version of the application to which you want to add the input processing configuration. You can use the <code>DescribeApplication</code> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    /// This field is required.
    pub fn current_application_version_id(mut self, input: i64) -> Self {
        self.current_application_version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the application to which you want to add the input processing configuration. You can use the <code>DescribeApplication</code> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn set_current_application_version_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.current_application_version_id = input;
        self
    }
    /// <p>The version of the application to which you want to add the input processing configuration. You can use the <code>DescribeApplication</code> operation to get the current application version. If the version specified is not the current version, the <code>ConcurrentModificationException</code> is returned.</p>
    pub fn get_current_application_version_id(&self) -> &::std::option::Option<i64> {
        &self.current_application_version_id
    }
    /// <p>The ID of the input configuration to add the input processing configuration to. You can get a list of the input IDs for an application using the <code>DescribeApplication</code> operation.</p>
    /// This field is required.
    pub fn input_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the input configuration to add the input processing configuration to. You can get a list of the input IDs for an application using the <code>DescribeApplication</code> operation.</p>
    pub fn set_input_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_id = input;
        self
    }
    /// <p>The ID of the input configuration to add the input processing configuration to. You can get a list of the input IDs for an application using the <code>DescribeApplication</code> operation.</p>
    pub fn get_input_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_id
    }
    /// <p>The <code>InputProcessingConfiguration</code> to add to the application.</p>
    /// This field is required.
    pub fn input_processing_configuration(mut self, input: crate::types::InputProcessingConfiguration) -> Self {
        self.input_processing_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>InputProcessingConfiguration</code> to add to the application.</p>
    pub fn set_input_processing_configuration(mut self, input: ::std::option::Option<crate::types::InputProcessingConfiguration>) -> Self {
        self.input_processing_configuration = input;
        self
    }
    /// <p>The <code>InputProcessingConfiguration</code> to add to the application.</p>
    pub fn get_input_processing_configuration(&self) -> &::std::option::Option<crate::types::InputProcessingConfiguration> {
        &self.input_processing_configuration
    }
    /// Consumes the builder and constructs a [`AddApplicationInputProcessingConfigurationInput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationInput {
                application_name: self.application_name,
                current_application_version_id: self.current_application_version_id,
                input_id: self.input_id,
                input_processing_configuration: self.input_processing_configuration,
            },
        )
    }
}
