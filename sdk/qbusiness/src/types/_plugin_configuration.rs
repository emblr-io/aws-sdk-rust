// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information required to invoke chat in <code>PLUGIN_MODE</code>.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/guardrails.html">Admin controls and guardrails</a>, <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/plugins.html">Plugins</a>, and <a href="https://docs.aws.amazon.com/amazonq/latest/business-use-dg/using-web-experience.html#chat-source-scope">Conversation settings</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PluginConfiguration {
    /// <p>The identifier of the plugin you want to use.</p>
    pub plugin_id: ::std::string::String,
}
impl PluginConfiguration {
    /// <p>The identifier of the plugin you want to use.</p>
    pub fn plugin_id(&self) -> &str {
        use std::ops::Deref;
        self.plugin_id.deref()
    }
}
impl PluginConfiguration {
    /// Creates a new builder-style object to manufacture [`PluginConfiguration`](crate::types::PluginConfiguration).
    pub fn builder() -> crate::types::builders::PluginConfigurationBuilder {
        crate::types::builders::PluginConfigurationBuilder::default()
    }
}

/// A builder for [`PluginConfiguration`](crate::types::PluginConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PluginConfigurationBuilder {
    pub(crate) plugin_id: ::std::option::Option<::std::string::String>,
}
impl PluginConfigurationBuilder {
    /// <p>The identifier of the plugin you want to use.</p>
    /// This field is required.
    pub fn plugin_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.plugin_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the plugin you want to use.</p>
    pub fn set_plugin_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.plugin_id = input;
        self
    }
    /// <p>The identifier of the plugin you want to use.</p>
    pub fn get_plugin_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.plugin_id
    }
    /// Consumes the builder and constructs a [`PluginConfiguration`](crate::types::PluginConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`plugin_id`](crate::types::builders::PluginConfigurationBuilder::plugin_id)
    pub fn build(self) -> ::std::result::Result<crate::types::PluginConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PluginConfiguration {
            plugin_id: self.plugin_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "plugin_id",
                    "plugin_id was not specified but it is required when building PluginConfiguration",
                )
            })?,
        })
    }
}
