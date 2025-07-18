// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to add specific VDM settings to a configuration set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutConfigurationSetVdmOptionsInput {
    /// <p>The name of the configuration set.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The VDM options to apply to the configuration set.</p>
    pub vdm_options: ::std::option::Option<crate::types::VdmOptions>,
}
impl PutConfigurationSetVdmOptionsInput {
    /// <p>The name of the configuration set.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>The VDM options to apply to the configuration set.</p>
    pub fn vdm_options(&self) -> ::std::option::Option<&crate::types::VdmOptions> {
        self.vdm_options.as_ref()
    }
}
impl PutConfigurationSetVdmOptionsInput {
    /// Creates a new builder-style object to manufacture [`PutConfigurationSetVdmOptionsInput`](crate::operation::put_configuration_set_vdm_options::PutConfigurationSetVdmOptionsInput).
    pub fn builder() -> crate::operation::put_configuration_set_vdm_options::builders::PutConfigurationSetVdmOptionsInputBuilder {
        crate::operation::put_configuration_set_vdm_options::builders::PutConfigurationSetVdmOptionsInputBuilder::default()
    }
}

/// A builder for [`PutConfigurationSetVdmOptionsInput`](crate::operation::put_configuration_set_vdm_options::PutConfigurationSetVdmOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutConfigurationSetVdmOptionsInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) vdm_options: ::std::option::Option<crate::types::VdmOptions>,
}
impl PutConfigurationSetVdmOptionsInputBuilder {
    /// <p>The name of the configuration set.</p>
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>The VDM options to apply to the configuration set.</p>
    pub fn vdm_options(mut self, input: crate::types::VdmOptions) -> Self {
        self.vdm_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VDM options to apply to the configuration set.</p>
    pub fn set_vdm_options(mut self, input: ::std::option::Option<crate::types::VdmOptions>) -> Self {
        self.vdm_options = input;
        self
    }
    /// <p>The VDM options to apply to the configuration set.</p>
    pub fn get_vdm_options(&self) -> &::std::option::Option<crate::types::VdmOptions> {
        &self.vdm_options
    }
    /// Consumes the builder and constructs a [`PutConfigurationSetVdmOptionsInput`](crate::operation::put_configuration_set_vdm_options::PutConfigurationSetVdmOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_configuration_set_vdm_options::PutConfigurationSetVdmOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_configuration_set_vdm_options::PutConfigurationSetVdmOptionsInput {
            configuration_set_name: self.configuration_set_name,
            vdm_options: self.vdm_options,
        })
    }
}
