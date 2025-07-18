// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartEdgeConfigurationUpdateInput {
    /// <p>The name of the stream whose edge configuration you want to update. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the stream. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>The edge configuration details required to invoke the update process.</p>
    pub edge_config: ::std::option::Option<crate::types::EdgeConfig>,
}
impl StartEdgeConfigurationUpdateInput {
    /// <p>The name of the stream whose edge configuration you want to update. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the stream. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>The edge configuration details required to invoke the update process.</p>
    pub fn edge_config(&self) -> ::std::option::Option<&crate::types::EdgeConfig> {
        self.edge_config.as_ref()
    }
}
impl StartEdgeConfigurationUpdateInput {
    /// Creates a new builder-style object to manufacture [`StartEdgeConfigurationUpdateInput`](crate::operation::start_edge_configuration_update::StartEdgeConfigurationUpdateInput).
    pub fn builder() -> crate::operation::start_edge_configuration_update::builders::StartEdgeConfigurationUpdateInputBuilder {
        crate::operation::start_edge_configuration_update::builders::StartEdgeConfigurationUpdateInputBuilder::default()
    }
}

/// A builder for [`StartEdgeConfigurationUpdateInput`](crate::operation::start_edge_configuration_update::StartEdgeConfigurationUpdateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartEdgeConfigurationUpdateInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) edge_config: ::std::option::Option<crate::types::EdgeConfig>,
}
impl StartEdgeConfigurationUpdateInputBuilder {
    /// <p>The name of the stream whose edge configuration you want to update. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream whose edge configuration you want to update. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream whose edge configuration you want to update. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The Amazon Resource Name (ARN) of the stream. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream. Specify either the <code>StreamName</code> or the <code>StreamARN</code>.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The edge configuration details required to invoke the update process.</p>
    /// This field is required.
    pub fn edge_config(mut self, input: crate::types::EdgeConfig) -> Self {
        self.edge_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The edge configuration details required to invoke the update process.</p>
    pub fn set_edge_config(mut self, input: ::std::option::Option<crate::types::EdgeConfig>) -> Self {
        self.edge_config = input;
        self
    }
    /// <p>The edge configuration details required to invoke the update process.</p>
    pub fn get_edge_config(&self) -> &::std::option::Option<crate::types::EdgeConfig> {
        &self.edge_config
    }
    /// Consumes the builder and constructs a [`StartEdgeConfigurationUpdateInput`](crate::operation::start_edge_configuration_update::StartEdgeConfigurationUpdateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_edge_configuration_update::StartEdgeConfigurationUpdateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_edge_configuration_update::StartEdgeConfigurationUpdateInput {
            stream_name: self.stream_name,
            stream_arn: self.stream_arn,
            edge_config: self.edge_config,
        })
    }
}
