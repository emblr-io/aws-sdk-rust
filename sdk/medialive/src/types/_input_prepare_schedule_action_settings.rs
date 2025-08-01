// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Action to prepare an input for a future immediate input switch.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputPrepareScheduleActionSettings {
    /// The name of the input attachment that should be prepared by this action. If no name is provided, the action will stop the most recent prepare (if any) when activated.
    pub input_attachment_name_reference: ::std::option::Option<::std::string::String>,
    /// Settings to let you create a clip of the file input, in order to set up the input to ingest only a portion of the file.
    pub input_clipping_settings: ::std::option::Option<crate::types::InputClippingSettings>,
    /// The value for the variable portion of the URL for the dynamic input, for this instance of the input. Each time you use the same dynamic input in an input switch action, you can provide a different value, in order to connect the input to a different content source.
    pub url_path: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl InputPrepareScheduleActionSettings {
    /// The name of the input attachment that should be prepared by this action. If no name is provided, the action will stop the most recent prepare (if any) when activated.
    pub fn input_attachment_name_reference(&self) -> ::std::option::Option<&str> {
        self.input_attachment_name_reference.as_deref()
    }
    /// Settings to let you create a clip of the file input, in order to set up the input to ingest only a portion of the file.
    pub fn input_clipping_settings(&self) -> ::std::option::Option<&crate::types::InputClippingSettings> {
        self.input_clipping_settings.as_ref()
    }
    /// The value for the variable portion of the URL for the dynamic input, for this instance of the input. Each time you use the same dynamic input in an input switch action, you can provide a different value, in order to connect the input to a different content source.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.url_path.is_none()`.
    pub fn url_path(&self) -> &[::std::string::String] {
        self.url_path.as_deref().unwrap_or_default()
    }
}
impl InputPrepareScheduleActionSettings {
    /// Creates a new builder-style object to manufacture [`InputPrepareScheduleActionSettings`](crate::types::InputPrepareScheduleActionSettings).
    pub fn builder() -> crate::types::builders::InputPrepareScheduleActionSettingsBuilder {
        crate::types::builders::InputPrepareScheduleActionSettingsBuilder::default()
    }
}

/// A builder for [`InputPrepareScheduleActionSettings`](crate::types::InputPrepareScheduleActionSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputPrepareScheduleActionSettingsBuilder {
    pub(crate) input_attachment_name_reference: ::std::option::Option<::std::string::String>,
    pub(crate) input_clipping_settings: ::std::option::Option<crate::types::InputClippingSettings>,
    pub(crate) url_path: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl InputPrepareScheduleActionSettingsBuilder {
    /// The name of the input attachment that should be prepared by this action. If no name is provided, the action will stop the most recent prepare (if any) when activated.
    pub fn input_attachment_name_reference(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_attachment_name_reference = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of the input attachment that should be prepared by this action. If no name is provided, the action will stop the most recent prepare (if any) when activated.
    pub fn set_input_attachment_name_reference(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_attachment_name_reference = input;
        self
    }
    /// The name of the input attachment that should be prepared by this action. If no name is provided, the action will stop the most recent prepare (if any) when activated.
    pub fn get_input_attachment_name_reference(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_attachment_name_reference
    }
    /// Settings to let you create a clip of the file input, in order to set up the input to ingest only a portion of the file.
    pub fn input_clipping_settings(mut self, input: crate::types::InputClippingSettings) -> Self {
        self.input_clipping_settings = ::std::option::Option::Some(input);
        self
    }
    /// Settings to let you create a clip of the file input, in order to set up the input to ingest only a portion of the file.
    pub fn set_input_clipping_settings(mut self, input: ::std::option::Option<crate::types::InputClippingSettings>) -> Self {
        self.input_clipping_settings = input;
        self
    }
    /// Settings to let you create a clip of the file input, in order to set up the input to ingest only a portion of the file.
    pub fn get_input_clipping_settings(&self) -> &::std::option::Option<crate::types::InputClippingSettings> {
        &self.input_clipping_settings
    }
    /// Appends an item to `url_path`.
    ///
    /// To override the contents of this collection use [`set_url_path`](Self::set_url_path).
    ///
    /// The value for the variable portion of the URL for the dynamic input, for this instance of the input. Each time you use the same dynamic input in an input switch action, you can provide a different value, in order to connect the input to a different content source.
    pub fn url_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.url_path.unwrap_or_default();
        v.push(input.into());
        self.url_path = ::std::option::Option::Some(v);
        self
    }
    /// The value for the variable portion of the URL for the dynamic input, for this instance of the input. Each time you use the same dynamic input in an input switch action, you can provide a different value, in order to connect the input to a different content source.
    pub fn set_url_path(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.url_path = input;
        self
    }
    /// The value for the variable portion of the URL for the dynamic input, for this instance of the input. Each time you use the same dynamic input in an input switch action, you can provide a different value, in order to connect the input to a different content source.
    pub fn get_url_path(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.url_path
    }
    /// Consumes the builder and constructs a [`InputPrepareScheduleActionSettings`](crate::types::InputPrepareScheduleActionSettings).
    pub fn build(self) -> crate::types::InputPrepareScheduleActionSettings {
        crate::types::InputPrepareScheduleActionSettings {
            input_attachment_name_reference: self.input_attachment_name_reference,
            input_clipping_settings: self.input_clipping_settings,
            url_path: self.url_path,
        }
    }
}
