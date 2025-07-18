// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Settings for a model called with <code>InvokeInlineAgent</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InlineBedrockModelConfigurations {
    /// <p>The latency configuration for the model.</p>
    pub performance_config: ::std::option::Option<crate::types::PerformanceConfiguration>,
}
impl InlineBedrockModelConfigurations {
    /// <p>The latency configuration for the model.</p>
    pub fn performance_config(&self) -> ::std::option::Option<&crate::types::PerformanceConfiguration> {
        self.performance_config.as_ref()
    }
}
impl InlineBedrockModelConfigurations {
    /// Creates a new builder-style object to manufacture [`InlineBedrockModelConfigurations`](crate::types::InlineBedrockModelConfigurations).
    pub fn builder() -> crate::types::builders::InlineBedrockModelConfigurationsBuilder {
        crate::types::builders::InlineBedrockModelConfigurationsBuilder::default()
    }
}

/// A builder for [`InlineBedrockModelConfigurations`](crate::types::InlineBedrockModelConfigurations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InlineBedrockModelConfigurationsBuilder {
    pub(crate) performance_config: ::std::option::Option<crate::types::PerformanceConfiguration>,
}
impl InlineBedrockModelConfigurationsBuilder {
    /// <p>The latency configuration for the model.</p>
    pub fn performance_config(mut self, input: crate::types::PerformanceConfiguration) -> Self {
        self.performance_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The latency configuration for the model.</p>
    pub fn set_performance_config(mut self, input: ::std::option::Option<crate::types::PerformanceConfiguration>) -> Self {
        self.performance_config = input;
        self
    }
    /// <p>The latency configuration for the model.</p>
    pub fn get_performance_config(&self) -> &::std::option::Option<crate::types::PerformanceConfiguration> {
        &self.performance_config
    }
    /// Consumes the builder and constructs a [`InlineBedrockModelConfigurations`](crate::types::InlineBedrockModelConfigurations).
    pub fn build(self) -> crate::types::InlineBedrockModelConfigurations {
        crate::types::InlineBedrockModelConfigurations {
            performance_config: self.performance_config,
        }
    }
}
