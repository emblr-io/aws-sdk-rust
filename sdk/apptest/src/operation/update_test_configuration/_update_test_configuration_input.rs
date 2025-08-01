// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTestConfigurationInput {
    /// <p>The test configuration ID of the test configuration.</p>
    pub test_configuration_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the test configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The resources of the test configuration.</p>
    pub resources: ::std::option::Option<::std::vec::Vec<crate::types::Resource>>,
    /// <p>The properties of the test configuration.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The service settings of the test configuration.</p>
    pub service_settings: ::std::option::Option<crate::types::ServiceSettings>,
}
impl UpdateTestConfigurationInput {
    /// <p>The test configuration ID of the test configuration.</p>
    pub fn test_configuration_id(&self) -> ::std::option::Option<&str> {
        self.test_configuration_id.as_deref()
    }
    /// <p>The description of the test configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The resources of the test configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resources.is_none()`.
    pub fn resources(&self) -> &[crate::types::Resource] {
        self.resources.as_deref().unwrap_or_default()
    }
    /// <p>The properties of the test configuration.</p>
    pub fn properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.properties.as_ref()
    }
    /// <p>The service settings of the test configuration.</p>
    pub fn service_settings(&self) -> ::std::option::Option<&crate::types::ServiceSettings> {
        self.service_settings.as_ref()
    }
}
impl UpdateTestConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateTestConfigurationInput`](crate::operation::update_test_configuration::UpdateTestConfigurationInput).
    pub fn builder() -> crate::operation::update_test_configuration::builders::UpdateTestConfigurationInputBuilder {
        crate::operation::update_test_configuration::builders::UpdateTestConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateTestConfigurationInput`](crate::operation::update_test_configuration::UpdateTestConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTestConfigurationInputBuilder {
    pub(crate) test_configuration_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) resources: ::std::option::Option<::std::vec::Vec<crate::types::Resource>>,
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) service_settings: ::std::option::Option<crate::types::ServiceSettings>,
}
impl UpdateTestConfigurationInputBuilder {
    /// <p>The test configuration ID of the test configuration.</p>
    /// This field is required.
    pub fn test_configuration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_configuration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test configuration ID of the test configuration.</p>
    pub fn set_test_configuration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_configuration_id = input;
        self
    }
    /// <p>The test configuration ID of the test configuration.</p>
    pub fn get_test_configuration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_configuration_id
    }
    /// <p>The description of the test configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the test configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the test configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `resources`.
    ///
    /// To override the contents of this collection use [`set_resources`](Self::set_resources).
    ///
    /// <p>The resources of the test configuration.</p>
    pub fn resources(mut self, input: crate::types::Resource) -> Self {
        let mut v = self.resources.unwrap_or_default();
        v.push(input);
        self.resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The resources of the test configuration.</p>
    pub fn set_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Resource>>) -> Self {
        self.resources = input;
        self
    }
    /// <p>The resources of the test configuration.</p>
    pub fn get_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Resource>> {
        &self.resources
    }
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>The properties of the test configuration.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The properties of the test configuration.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The properties of the test configuration.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.properties
    }
    /// <p>The service settings of the test configuration.</p>
    pub fn service_settings(mut self, input: crate::types::ServiceSettings) -> Self {
        self.service_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The service settings of the test configuration.</p>
    pub fn set_service_settings(mut self, input: ::std::option::Option<crate::types::ServiceSettings>) -> Self {
        self.service_settings = input;
        self
    }
    /// <p>The service settings of the test configuration.</p>
    pub fn get_service_settings(&self) -> &::std::option::Option<crate::types::ServiceSettings> {
        &self.service_settings
    }
    /// Consumes the builder and constructs a [`UpdateTestConfigurationInput`](crate::operation::update_test_configuration::UpdateTestConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_test_configuration::UpdateTestConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_test_configuration::UpdateTestConfigurationInput {
            test_configuration_id: self.test_configuration_id,
            description: self.description,
            resources: self.resources,
            properties: self.properties,
            service_settings: self.service_settings,
        })
    }
}
