// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object for you to specify your overrides for the recording mode.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecordingModeOverride {
    /// <p>A description that you provide for the override.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A comma-separated list that specifies which resource types Config includes in the override.</p><important>
    /// <p>Daily recording cannot be specified for the following resource types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS::Config::ResourceCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConformancePackCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConfigurationRecorder</code></p></li>
    /// </ul>
    /// </important>
    pub resource_types: ::std::vec::Vec<crate::types::ResourceType>,
    /// <p>The recording frequency that will be applied to all the resource types specified in the override.</p>
    /// <ul>
    /// <li>
    /// <p>Continuous recording allows you to record configuration changes continuously whenever a change occurs.</p></li>
    /// <li>
    /// <p>Daily recording allows you to receive a configuration item (CI) representing the most recent state of your resources over the last 24-hour period, only if it’s different from the previous CI recorded.</p></li>
    /// </ul><note>
    /// <p>Firewall Manager depends on continuous recording to monitor your resources. If you are using Firewall Manager, it is recommended that you set the recording frequency to Continuous.</p>
    /// </note>
    pub recording_frequency: crate::types::RecordingFrequency,
}
impl RecordingModeOverride {
    /// <p>A description that you provide for the override.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A comma-separated list that specifies which resource types Config includes in the override.</p><important>
    /// <p>Daily recording cannot be specified for the following resource types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS::Config::ResourceCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConformancePackCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConfigurationRecorder</code></p></li>
    /// </ul>
    /// </important>
    pub fn resource_types(&self) -> &[crate::types::ResourceType] {
        use std::ops::Deref;
        self.resource_types.deref()
    }
    /// <p>The recording frequency that will be applied to all the resource types specified in the override.</p>
    /// <ul>
    /// <li>
    /// <p>Continuous recording allows you to record configuration changes continuously whenever a change occurs.</p></li>
    /// <li>
    /// <p>Daily recording allows you to receive a configuration item (CI) representing the most recent state of your resources over the last 24-hour period, only if it’s different from the previous CI recorded.</p></li>
    /// </ul><note>
    /// <p>Firewall Manager depends on continuous recording to monitor your resources. If you are using Firewall Manager, it is recommended that you set the recording frequency to Continuous.</p>
    /// </note>
    pub fn recording_frequency(&self) -> &crate::types::RecordingFrequency {
        &self.recording_frequency
    }
}
impl RecordingModeOverride {
    /// Creates a new builder-style object to manufacture [`RecordingModeOverride`](crate::types::RecordingModeOverride).
    pub fn builder() -> crate::types::builders::RecordingModeOverrideBuilder {
        crate::types::builders::RecordingModeOverrideBuilder::default()
    }
}

/// A builder for [`RecordingModeOverride`](crate::types::RecordingModeOverride).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecordingModeOverrideBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) resource_types: ::std::option::Option<::std::vec::Vec<crate::types::ResourceType>>,
    pub(crate) recording_frequency: ::std::option::Option<crate::types::RecordingFrequency>,
}
impl RecordingModeOverrideBuilder {
    /// <p>A description that you provide for the override.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description that you provide for the override.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description that you provide for the override.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `resource_types`.
    ///
    /// To override the contents of this collection use [`set_resource_types`](Self::set_resource_types).
    ///
    /// <p>A comma-separated list that specifies which resource types Config includes in the override.</p><important>
    /// <p>Daily recording cannot be specified for the following resource types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS::Config::ResourceCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConformancePackCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConfigurationRecorder</code></p></li>
    /// </ul>
    /// </important>
    pub fn resource_types(mut self, input: crate::types::ResourceType) -> Self {
        let mut v = self.resource_types.unwrap_or_default();
        v.push(input);
        self.resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>A comma-separated list that specifies which resource types Config includes in the override.</p><important>
    /// <p>Daily recording cannot be specified for the following resource types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS::Config::ResourceCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConformancePackCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConfigurationRecorder</code></p></li>
    /// </ul>
    /// </important>
    pub fn set_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceType>>) -> Self {
        self.resource_types = input;
        self
    }
    /// <p>A comma-separated list that specifies which resource types Config includes in the override.</p><important>
    /// <p>Daily recording cannot be specified for the following resource types:</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS::Config::ResourceCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConformancePackCompliance</code></p></li>
    /// <li>
    /// <p><code>AWS::Config::ConfigurationRecorder</code></p></li>
    /// </ul>
    /// </important>
    pub fn get_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceType>> {
        &self.resource_types
    }
    /// <p>The recording frequency that will be applied to all the resource types specified in the override.</p>
    /// <ul>
    /// <li>
    /// <p>Continuous recording allows you to record configuration changes continuously whenever a change occurs.</p></li>
    /// <li>
    /// <p>Daily recording allows you to receive a configuration item (CI) representing the most recent state of your resources over the last 24-hour period, only if it’s different from the previous CI recorded.</p></li>
    /// </ul><note>
    /// <p>Firewall Manager depends on continuous recording to monitor your resources. If you are using Firewall Manager, it is recommended that you set the recording frequency to Continuous.</p>
    /// </note>
    /// This field is required.
    pub fn recording_frequency(mut self, input: crate::types::RecordingFrequency) -> Self {
        self.recording_frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recording frequency that will be applied to all the resource types specified in the override.</p>
    /// <ul>
    /// <li>
    /// <p>Continuous recording allows you to record configuration changes continuously whenever a change occurs.</p></li>
    /// <li>
    /// <p>Daily recording allows you to receive a configuration item (CI) representing the most recent state of your resources over the last 24-hour period, only if it’s different from the previous CI recorded.</p></li>
    /// </ul><note>
    /// <p>Firewall Manager depends on continuous recording to monitor your resources. If you are using Firewall Manager, it is recommended that you set the recording frequency to Continuous.</p>
    /// </note>
    pub fn set_recording_frequency(mut self, input: ::std::option::Option<crate::types::RecordingFrequency>) -> Self {
        self.recording_frequency = input;
        self
    }
    /// <p>The recording frequency that will be applied to all the resource types specified in the override.</p>
    /// <ul>
    /// <li>
    /// <p>Continuous recording allows you to record configuration changes continuously whenever a change occurs.</p></li>
    /// <li>
    /// <p>Daily recording allows you to receive a configuration item (CI) representing the most recent state of your resources over the last 24-hour period, only if it’s different from the previous CI recorded.</p></li>
    /// </ul><note>
    /// <p>Firewall Manager depends on continuous recording to monitor your resources. If you are using Firewall Manager, it is recommended that you set the recording frequency to Continuous.</p>
    /// </note>
    pub fn get_recording_frequency(&self) -> &::std::option::Option<crate::types::RecordingFrequency> {
        &self.recording_frequency
    }
    /// Consumes the builder and constructs a [`RecordingModeOverride`](crate::types::RecordingModeOverride).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_types`](crate::types::builders::RecordingModeOverrideBuilder::resource_types)
    /// - [`recording_frequency`](crate::types::builders::RecordingModeOverrideBuilder::recording_frequency)
    pub fn build(self) -> ::std::result::Result<crate::types::RecordingModeOverride, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecordingModeOverride {
            description: self.description,
            resource_types: self.resource_types.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_types",
                    "resource_types was not specified but it is required when building RecordingModeOverride",
                )
            })?,
            recording_frequency: self.recording_frequency.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recording_frequency",
                    "recording_frequency was not specified but it is required when building RecordingModeOverride",
                )
            })?,
        })
    }
}
