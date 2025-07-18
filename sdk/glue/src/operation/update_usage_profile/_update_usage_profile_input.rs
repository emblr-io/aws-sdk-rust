// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateUsageProfileInput {
    /// <p>The name of the usage profile.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the usage profile.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A <code>ProfileConfiguration</code> object specifying the job and session values for the profile.</p>
    pub configuration: ::std::option::Option<crate::types::ProfileConfiguration>,
}
impl UpdateUsageProfileInput {
    /// <p>The name of the usage profile.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the usage profile.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A <code>ProfileConfiguration</code> object specifying the job and session values for the profile.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::ProfileConfiguration> {
        self.configuration.as_ref()
    }
}
impl UpdateUsageProfileInput {
    /// Creates a new builder-style object to manufacture [`UpdateUsageProfileInput`](crate::operation::update_usage_profile::UpdateUsageProfileInput).
    pub fn builder() -> crate::operation::update_usage_profile::builders::UpdateUsageProfileInputBuilder {
        crate::operation::update_usage_profile::builders::UpdateUsageProfileInputBuilder::default()
    }
}

/// A builder for [`UpdateUsageProfileInput`](crate::operation::update_usage_profile::UpdateUsageProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateUsageProfileInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::ProfileConfiguration>,
}
impl UpdateUsageProfileInputBuilder {
    /// <p>The name of the usage profile.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the usage profile.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the usage profile.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the usage profile.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the usage profile.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the usage profile.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A <code>ProfileConfiguration</code> object specifying the job and session values for the profile.</p>
    /// This field is required.
    pub fn configuration(mut self, input: crate::types::ProfileConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>ProfileConfiguration</code> object specifying the job and session values for the profile.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::ProfileConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>A <code>ProfileConfiguration</code> object specifying the job and session values for the profile.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::ProfileConfiguration> {
        &self.configuration
    }
    /// Consumes the builder and constructs a [`UpdateUsageProfileInput`](crate::operation::update_usage_profile::UpdateUsageProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_usage_profile::UpdateUsageProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_usage_profile::UpdateUsageProfileInput {
            name: self.name,
            description: self.description,
            configuration: self.configuration,
        })
    }
}
