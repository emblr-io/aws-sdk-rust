// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Group of outputs
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OutputGroup {
    /// Use automated encoding to have MediaConvert choose your encoding settings for you, based on characteristics of your input video.
    pub automated_encoding_settings: ::std::option::Option<crate::types::AutomatedEncodingSettings>,
    /// Use Custom Group Name to specify a name for the output group. This value is displayed on the console and can make your job settings JSON more human-readable. It does not affect your outputs. Use up to twelve characters that are either letters, numbers, spaces, or underscores.
    pub custom_name: ::std::option::Option<::std::string::String>,
    /// Name of the output group
    pub name: ::std::option::Option<::std::string::String>,
    /// Output Group settings, including type
    pub output_group_settings: ::std::option::Option<crate::types::OutputGroupSettings>,
    /// This object holds groups of encoding settings, one group of settings per output.
    pub outputs: ::std::option::Option<::std::vec::Vec<crate::types::Output>>,
}
impl OutputGroup {
    /// Use automated encoding to have MediaConvert choose your encoding settings for you, based on characteristics of your input video.
    pub fn automated_encoding_settings(&self) -> ::std::option::Option<&crate::types::AutomatedEncodingSettings> {
        self.automated_encoding_settings.as_ref()
    }
    /// Use Custom Group Name to specify a name for the output group. This value is displayed on the console and can make your job settings JSON more human-readable. It does not affect your outputs. Use up to twelve characters that are either letters, numbers, spaces, or underscores.
    pub fn custom_name(&self) -> ::std::option::Option<&str> {
        self.custom_name.as_deref()
    }
    /// Name of the output group
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// Output Group settings, including type
    pub fn output_group_settings(&self) -> ::std::option::Option<&crate::types::OutputGroupSettings> {
        self.output_group_settings.as_ref()
    }
    /// This object holds groups of encoding settings, one group of settings per output.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.outputs.is_none()`.
    pub fn outputs(&self) -> &[crate::types::Output] {
        self.outputs.as_deref().unwrap_or_default()
    }
}
impl OutputGroup {
    /// Creates a new builder-style object to manufacture [`OutputGroup`](crate::types::OutputGroup).
    pub fn builder() -> crate::types::builders::OutputGroupBuilder {
        crate::types::builders::OutputGroupBuilder::default()
    }
}

/// A builder for [`OutputGroup`](crate::types::OutputGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OutputGroupBuilder {
    pub(crate) automated_encoding_settings: ::std::option::Option<crate::types::AutomatedEncodingSettings>,
    pub(crate) custom_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) output_group_settings: ::std::option::Option<crate::types::OutputGroupSettings>,
    pub(crate) outputs: ::std::option::Option<::std::vec::Vec<crate::types::Output>>,
}
impl OutputGroupBuilder {
    /// Use automated encoding to have MediaConvert choose your encoding settings for you, based on characteristics of your input video.
    pub fn automated_encoding_settings(mut self, input: crate::types::AutomatedEncodingSettings) -> Self {
        self.automated_encoding_settings = ::std::option::Option::Some(input);
        self
    }
    /// Use automated encoding to have MediaConvert choose your encoding settings for you, based on characteristics of your input video.
    pub fn set_automated_encoding_settings(mut self, input: ::std::option::Option<crate::types::AutomatedEncodingSettings>) -> Self {
        self.automated_encoding_settings = input;
        self
    }
    /// Use automated encoding to have MediaConvert choose your encoding settings for you, based on characteristics of your input video.
    pub fn get_automated_encoding_settings(&self) -> &::std::option::Option<crate::types::AutomatedEncodingSettings> {
        &self.automated_encoding_settings
    }
    /// Use Custom Group Name to specify a name for the output group. This value is displayed on the console and can make your job settings JSON more human-readable. It does not affect your outputs. Use up to twelve characters that are either letters, numbers, spaces, or underscores.
    pub fn custom_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_name = ::std::option::Option::Some(input.into());
        self
    }
    /// Use Custom Group Name to specify a name for the output group. This value is displayed on the console and can make your job settings JSON more human-readable. It does not affect your outputs. Use up to twelve characters that are either letters, numbers, spaces, or underscores.
    pub fn set_custom_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_name = input;
        self
    }
    /// Use Custom Group Name to specify a name for the output group. This value is displayed on the console and can make your job settings JSON more human-readable. It does not affect your outputs. Use up to twelve characters that are either letters, numbers, spaces, or underscores.
    pub fn get_custom_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_name
    }
    /// Name of the output group
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// Name of the output group
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// Name of the output group
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Output Group settings, including type
    pub fn output_group_settings(mut self, input: crate::types::OutputGroupSettings) -> Self {
        self.output_group_settings = ::std::option::Option::Some(input);
        self
    }
    /// Output Group settings, including type
    pub fn set_output_group_settings(mut self, input: ::std::option::Option<crate::types::OutputGroupSettings>) -> Self {
        self.output_group_settings = input;
        self
    }
    /// Output Group settings, including type
    pub fn get_output_group_settings(&self) -> &::std::option::Option<crate::types::OutputGroupSettings> {
        &self.output_group_settings
    }
    /// Appends an item to `outputs`.
    ///
    /// To override the contents of this collection use [`set_outputs`](Self::set_outputs).
    ///
    /// This object holds groups of encoding settings, one group of settings per output.
    pub fn outputs(mut self, input: crate::types::Output) -> Self {
        let mut v = self.outputs.unwrap_or_default();
        v.push(input);
        self.outputs = ::std::option::Option::Some(v);
        self
    }
    /// This object holds groups of encoding settings, one group of settings per output.
    pub fn set_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Output>>) -> Self {
        self.outputs = input;
        self
    }
    /// This object holds groups of encoding settings, one group of settings per output.
    pub fn get_outputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Output>> {
        &self.outputs
    }
    /// Consumes the builder and constructs a [`OutputGroup`](crate::types::OutputGroup).
    pub fn build(self) -> crate::types::OutputGroup {
        crate::types::OutputGroup {
            automated_encoding_settings: self.automated_encoding_settings,
            custom_name: self.custom_name,
            name: self.name,
            output_group_settings: self.output_group_settings,
            outputs: self.outputs,
        }
    }
}
