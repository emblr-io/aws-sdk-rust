// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddApplicationInputProcessingConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>Provides the current application version.</p>
    pub application_version_id: ::std::option::Option<i64>,
    /// <p>The input ID that is associated with the application input. This is the ID that Kinesis Data Analytics assigns to each input configuration that you add to your application.</p>
    pub input_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the preprocessor that executes on records in this input before the application's code is run.</p>
    pub input_processing_configuration_description: ::std::option::Option<crate::types::InputProcessingConfigurationDescription>,
    _request_id: Option<String>,
}
impl AddApplicationInputProcessingConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>Provides the current application version.</p>
    pub fn application_version_id(&self) -> ::std::option::Option<i64> {
        self.application_version_id
    }
    /// <p>The input ID that is associated with the application input. This is the ID that Kinesis Data Analytics assigns to each input configuration that you add to your application.</p>
    pub fn input_id(&self) -> ::std::option::Option<&str> {
        self.input_id.as_deref()
    }
    /// <p>The description of the preprocessor that executes on records in this input before the application's code is run.</p>
    pub fn input_processing_configuration_description(&self) -> ::std::option::Option<&crate::types::InputProcessingConfigurationDescription> {
        self.input_processing_configuration_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AddApplicationInputProcessingConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AddApplicationInputProcessingConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`AddApplicationInputProcessingConfigurationOutput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationOutput).
    pub fn builder(
    ) -> crate::operation::add_application_input_processing_configuration::builders::AddApplicationInputProcessingConfigurationOutputBuilder {
        crate::operation::add_application_input_processing_configuration::builders::AddApplicationInputProcessingConfigurationOutputBuilder::default()
    }
}

/// A builder for [`AddApplicationInputProcessingConfigurationOutput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddApplicationInputProcessingConfigurationOutputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_version_id: ::std::option::Option<i64>,
    pub(crate) input_id: ::std::option::Option<::std::string::String>,
    pub(crate) input_processing_configuration_description: ::std::option::Option<crate::types::InputProcessingConfigurationDescription>,
    _request_id: Option<String>,
}
impl AddApplicationInputProcessingConfigurationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>Provides the current application version.</p>
    pub fn application_version_id(mut self, input: i64) -> Self {
        self.application_version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the current application version.</p>
    pub fn set_application_version_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.application_version_id = input;
        self
    }
    /// <p>Provides the current application version.</p>
    pub fn get_application_version_id(&self) -> &::std::option::Option<i64> {
        &self.application_version_id
    }
    /// <p>The input ID that is associated with the application input. This is the ID that Kinesis Data Analytics assigns to each input configuration that you add to your application.</p>
    pub fn input_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input ID that is associated with the application input. This is the ID that Kinesis Data Analytics assigns to each input configuration that you add to your application.</p>
    pub fn set_input_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_id = input;
        self
    }
    /// <p>The input ID that is associated with the application input. This is the ID that Kinesis Data Analytics assigns to each input configuration that you add to your application.</p>
    pub fn get_input_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_id
    }
    /// <p>The description of the preprocessor that executes on records in this input before the application's code is run.</p>
    pub fn input_processing_configuration_description(mut self, input: crate::types::InputProcessingConfigurationDescription) -> Self {
        self.input_processing_configuration_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>The description of the preprocessor that executes on records in this input before the application's code is run.</p>
    pub fn set_input_processing_configuration_description(
        mut self,
        input: ::std::option::Option<crate::types::InputProcessingConfigurationDescription>,
    ) -> Self {
        self.input_processing_configuration_description = input;
        self
    }
    /// <p>The description of the preprocessor that executes on records in this input before the application's code is run.</p>
    pub fn get_input_processing_configuration_description(&self) -> &::std::option::Option<crate::types::InputProcessingConfigurationDescription> {
        &self.input_processing_configuration_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AddApplicationInputProcessingConfigurationOutput`](crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationOutput).
    pub fn build(self) -> crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationOutput {
        crate::operation::add_application_input_processing_configuration::AddApplicationInputProcessingConfigurationOutput {
            application_arn: self.application_arn,
            application_version_id: self.application_version_id,
            input_id: self.input_id,
            input_processing_configuration_description: self.input_processing_configuration_description,
            _request_id: self._request_id,
        }
    }
}
