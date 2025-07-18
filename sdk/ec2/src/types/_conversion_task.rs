// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a conversion task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConversionTask {
    /// <p>The ID of the conversion task.</p>
    pub conversion_task_id: ::std::option::Option<::std::string::String>,
    /// <p>The time when the task expires. If the upload isn't complete before the expiration time, we automatically cancel the task.</p>
    pub expiration_time: ::std::option::Option<::std::string::String>,
    /// <p>If the task is for importing an instance, this contains information about the import instance task.</p>
    pub import_instance: ::std::option::Option<crate::types::ImportInstanceTaskDetails>,
    /// <p>If the task is for importing a volume, this contains information about the import volume task.</p>
    pub import_volume: ::std::option::Option<crate::types::ImportVolumeTaskDetails>,
    /// <p>The state of the conversion task.</p>
    pub state: ::std::option::Option<crate::types::ConversionTaskState>,
    /// <p>The status message related to the conversion task.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>Any tags assigned to the task.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ConversionTask {
    /// <p>The ID of the conversion task.</p>
    pub fn conversion_task_id(&self) -> ::std::option::Option<&str> {
        self.conversion_task_id.as_deref()
    }
    /// <p>The time when the task expires. If the upload isn't complete before the expiration time, we automatically cancel the task.</p>
    pub fn expiration_time(&self) -> ::std::option::Option<&str> {
        self.expiration_time.as_deref()
    }
    /// <p>If the task is for importing an instance, this contains information about the import instance task.</p>
    pub fn import_instance(&self) -> ::std::option::Option<&crate::types::ImportInstanceTaskDetails> {
        self.import_instance.as_ref()
    }
    /// <p>If the task is for importing a volume, this contains information about the import volume task.</p>
    pub fn import_volume(&self) -> ::std::option::Option<&crate::types::ImportVolumeTaskDetails> {
        self.import_volume.as_ref()
    }
    /// <p>The state of the conversion task.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::ConversionTaskState> {
        self.state.as_ref()
    }
    /// <p>The status message related to the conversion task.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>Any tags assigned to the task.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ConversionTask {
    /// Creates a new builder-style object to manufacture [`ConversionTask`](crate::types::ConversionTask).
    pub fn builder() -> crate::types::builders::ConversionTaskBuilder {
        crate::types::builders::ConversionTaskBuilder::default()
    }
}

/// A builder for [`ConversionTask`](crate::types::ConversionTask).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConversionTaskBuilder {
    pub(crate) conversion_task_id: ::std::option::Option<::std::string::String>,
    pub(crate) expiration_time: ::std::option::Option<::std::string::String>,
    pub(crate) import_instance: ::std::option::Option<crate::types::ImportInstanceTaskDetails>,
    pub(crate) import_volume: ::std::option::Option<crate::types::ImportVolumeTaskDetails>,
    pub(crate) state: ::std::option::Option<crate::types::ConversionTaskState>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ConversionTaskBuilder {
    /// <p>The ID of the conversion task.</p>
    pub fn conversion_task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conversion_task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the conversion task.</p>
    pub fn set_conversion_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conversion_task_id = input;
        self
    }
    /// <p>The ID of the conversion task.</p>
    pub fn get_conversion_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conversion_task_id
    }
    /// <p>The time when the task expires. If the upload isn't complete before the expiration time, we automatically cancel the task.</p>
    pub fn expiration_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expiration_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the task expires. If the upload isn't complete before the expiration time, we automatically cancel the task.</p>
    pub fn set_expiration_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expiration_time = input;
        self
    }
    /// <p>The time when the task expires. If the upload isn't complete before the expiration time, we automatically cancel the task.</p>
    pub fn get_expiration_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.expiration_time
    }
    /// <p>If the task is for importing an instance, this contains information about the import instance task.</p>
    pub fn import_instance(mut self, input: crate::types::ImportInstanceTaskDetails) -> Self {
        self.import_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the task is for importing an instance, this contains information about the import instance task.</p>
    pub fn set_import_instance(mut self, input: ::std::option::Option<crate::types::ImportInstanceTaskDetails>) -> Self {
        self.import_instance = input;
        self
    }
    /// <p>If the task is for importing an instance, this contains information about the import instance task.</p>
    pub fn get_import_instance(&self) -> &::std::option::Option<crate::types::ImportInstanceTaskDetails> {
        &self.import_instance
    }
    /// <p>If the task is for importing a volume, this contains information about the import volume task.</p>
    pub fn import_volume(mut self, input: crate::types::ImportVolumeTaskDetails) -> Self {
        self.import_volume = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the task is for importing a volume, this contains information about the import volume task.</p>
    pub fn set_import_volume(mut self, input: ::std::option::Option<crate::types::ImportVolumeTaskDetails>) -> Self {
        self.import_volume = input;
        self
    }
    /// <p>If the task is for importing a volume, this contains information about the import volume task.</p>
    pub fn get_import_volume(&self) -> &::std::option::Option<crate::types::ImportVolumeTaskDetails> {
        &self.import_volume
    }
    /// <p>The state of the conversion task.</p>
    pub fn state(mut self, input: crate::types::ConversionTaskState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the conversion task.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::ConversionTaskState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the conversion task.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::ConversionTaskState> {
        &self.state
    }
    /// <p>The status message related to the conversion task.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message related to the conversion task.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The status message related to the conversion task.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Any tags assigned to the task.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any tags assigned to the task.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Any tags assigned to the task.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ConversionTask`](crate::types::ConversionTask).
    pub fn build(self) -> crate::types::ConversionTask {
        crate::types::ConversionTask {
            conversion_task_id: self.conversion_task_id,
            expiration_time: self.expiration_time,
            import_instance: self.import_instance,
            import_volume: self.import_volume,
            state: self.state,
            status_message: self.status_message,
            tags: self.tags,
        }
    }
}
