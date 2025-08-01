// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to delete a configuration template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConfigurationTemplateInput {
    /// <p>The name of the application to delete the configuration template from.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the configuration template to delete.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationTemplateInput {
    /// <p>The name of the application to delete the configuration template from.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>The name of the configuration template to delete.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
}
impl DeleteConfigurationTemplateInput {
    /// Creates a new builder-style object to manufacture [`DeleteConfigurationTemplateInput`](crate::operation::delete_configuration_template::DeleteConfigurationTemplateInput).
    pub fn builder() -> crate::operation::delete_configuration_template::builders::DeleteConfigurationTemplateInputBuilder {
        crate::operation::delete_configuration_template::builders::DeleteConfigurationTemplateInputBuilder::default()
    }
}

/// A builder for [`DeleteConfigurationTemplateInput`](crate::operation::delete_configuration_template::DeleteConfigurationTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConfigurationTemplateInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationTemplateInputBuilder {
    /// <p>The name of the application to delete the configuration template from.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application to delete the configuration template from.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>The name of the application to delete the configuration template from.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>The name of the configuration template to delete.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration template to delete.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the configuration template to delete.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// Consumes the builder and constructs a [`DeleteConfigurationTemplateInput`](crate::operation::delete_configuration_template::DeleteConfigurationTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_configuration_template::DeleteConfigurationTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_configuration_template::DeleteConfigurationTemplateInput {
            application_name: self.application_name,
            template_name: self.template_name,
        })
    }
}
