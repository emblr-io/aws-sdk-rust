// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about a RecordingConfiguration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecordingConfigurationSummary {
    /// <p>Recording-configuration ARN.</p>
    pub arn: ::std::string::String,
    /// <p>Recording-configuration name. The value does not need to be unique.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A complex type that contains information about where recorded video will be stored.</p>
    pub destination_configuration: ::std::option::Option<crate::types::DestinationConfiguration>,
    /// <p>Indicates the current state of the recording configuration. When the state is <code>ACTIVE</code>, the configuration is ready for recording a channel stream.</p>
    pub state: crate::types::RecordingConfigurationState,
    /// <p>Tags attached to the resource. Array of 1-50 maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS has no service-specific constraints beyond what is documented there.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl RecordingConfigurationSummary {
    /// <p>Recording-configuration ARN.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>Recording-configuration name. The value does not need to be unique.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A complex type that contains information about where recorded video will be stored.</p>
    pub fn destination_configuration(&self) -> ::std::option::Option<&crate::types::DestinationConfiguration> {
        self.destination_configuration.as_ref()
    }
    /// <p>Indicates the current state of the recording configuration. When the state is <code>ACTIVE</code>, the configuration is ready for recording a channel stream.</p>
    pub fn state(&self) -> &crate::types::RecordingConfigurationState {
        &self.state
    }
    /// <p>Tags attached to the resource. Array of 1-50 maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS has no service-specific constraints beyond what is documented there.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl RecordingConfigurationSummary {
    /// Creates a new builder-style object to manufacture [`RecordingConfigurationSummary`](crate::types::RecordingConfigurationSummary).
    pub fn builder() -> crate::types::builders::RecordingConfigurationSummaryBuilder {
        crate::types::builders::RecordingConfigurationSummaryBuilder::default()
    }
}

/// A builder for [`RecordingConfigurationSummary`](crate::types::RecordingConfigurationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecordingConfigurationSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) destination_configuration: ::std::option::Option<crate::types::DestinationConfiguration>,
    pub(crate) state: ::std::option::Option<crate::types::RecordingConfigurationState>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl RecordingConfigurationSummaryBuilder {
    /// <p>Recording-configuration ARN.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Recording-configuration ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>Recording-configuration ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Recording-configuration name. The value does not need to be unique.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Recording-configuration name. The value does not need to be unique.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Recording-configuration name. The value does not need to be unique.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A complex type that contains information about where recorded video will be stored.</p>
    /// This field is required.
    pub fn destination_configuration(mut self, input: crate::types::DestinationConfiguration) -> Self {
        self.destination_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains information about where recorded video will be stored.</p>
    pub fn set_destination_configuration(mut self, input: ::std::option::Option<crate::types::DestinationConfiguration>) -> Self {
        self.destination_configuration = input;
        self
    }
    /// <p>A complex type that contains information about where recorded video will be stored.</p>
    pub fn get_destination_configuration(&self) -> &::std::option::Option<crate::types::DestinationConfiguration> {
        &self.destination_configuration
    }
    /// <p>Indicates the current state of the recording configuration. When the state is <code>ACTIVE</code>, the configuration is ready for recording a channel stream.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::RecordingConfigurationState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the current state of the recording configuration. When the state is <code>ACTIVE</code>, the configuration is ready for recording a channel stream.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::RecordingConfigurationState>) -> Self {
        self.state = input;
        self
    }
    /// <p>Indicates the current state of the recording configuration. When the state is <code>ACTIVE</code>, the configuration is ready for recording a channel stream.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::RecordingConfigurationState> {
        &self.state
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags attached to the resource. Array of 1-50 maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS has no service-specific constraints beyond what is documented there.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags attached to the resource. Array of 1-50 maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS has no service-specific constraints beyond what is documented there.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags attached to the resource. Array of 1-50 maps, each of the form <code>string:string (key:value)</code>. See <a href="https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html">Best practices and strategies</a> in <i>Tagging Amazon Web Services Resources and Tag Editor</i> for details, including restrictions that apply to tags and "Tag naming limits and requirements"; Amazon IVS has no service-specific constraints beyond what is documented there.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`RecordingConfigurationSummary`](crate::types::RecordingConfigurationSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::RecordingConfigurationSummaryBuilder::arn)
    /// - [`state`](crate::types::builders::RecordingConfigurationSummaryBuilder::state)
    pub fn build(self) -> ::std::result::Result<crate::types::RecordingConfigurationSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecordingConfigurationSummary {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building RecordingConfigurationSummary",
                )
            })?,
            name: self.name,
            destination_configuration: self.destination_configuration,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building RecordingConfigurationSummary",
                )
            })?,
            tags: self.tags,
        })
    }
}
