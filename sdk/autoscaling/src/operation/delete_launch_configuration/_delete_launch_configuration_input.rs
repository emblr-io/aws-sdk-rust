// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLaunchConfigurationInput {
    /// <p>The name of the launch configuration.</p>
    pub launch_configuration_name: ::std::option::Option<::std::string::String>,
}
impl DeleteLaunchConfigurationInput {
    /// <p>The name of the launch configuration.</p>
    pub fn launch_configuration_name(&self) -> ::std::option::Option<&str> {
        self.launch_configuration_name.as_deref()
    }
}
impl DeleteLaunchConfigurationInput {
    /// Creates a new builder-style object to manufacture [`DeleteLaunchConfigurationInput`](crate::operation::delete_launch_configuration::DeleteLaunchConfigurationInput).
    pub fn builder() -> crate::operation::delete_launch_configuration::builders::DeleteLaunchConfigurationInputBuilder {
        crate::operation::delete_launch_configuration::builders::DeleteLaunchConfigurationInputBuilder::default()
    }
}

/// A builder for [`DeleteLaunchConfigurationInput`](crate::operation::delete_launch_configuration::DeleteLaunchConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLaunchConfigurationInputBuilder {
    pub(crate) launch_configuration_name: ::std::option::Option<::std::string::String>,
}
impl DeleteLaunchConfigurationInputBuilder {
    /// <p>The name of the launch configuration.</p>
    /// This field is required.
    pub fn launch_configuration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.launch_configuration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the launch configuration.</p>
    pub fn set_launch_configuration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.launch_configuration_name = input;
        self
    }
    /// <p>The name of the launch configuration.</p>
    pub fn get_launch_configuration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.launch_configuration_name
    }
    /// Consumes the builder and constructs a [`DeleteLaunchConfigurationInput`](crate::operation::delete_launch_configuration::DeleteLaunchConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_launch_configuration::DeleteLaunchConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_launch_configuration::DeleteLaunchConfigurationInput {
            launch_configuration_name: self.launch_configuration_name,
        })
    }
}
