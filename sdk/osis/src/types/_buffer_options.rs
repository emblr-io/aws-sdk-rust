// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BufferOptions {
    /// <p>Whether persistent buffering should be enabled.</p>
    pub persistent_buffer_enabled: bool,
}
impl BufferOptions {
    /// <p>Whether persistent buffering should be enabled.</p>
    pub fn persistent_buffer_enabled(&self) -> bool {
        self.persistent_buffer_enabled
    }
}
impl BufferOptions {
    /// Creates a new builder-style object to manufacture [`BufferOptions`](crate::types::BufferOptions).
    pub fn builder() -> crate::types::builders::BufferOptionsBuilder {
        crate::types::builders::BufferOptionsBuilder::default()
    }
}

/// A builder for [`BufferOptions`](crate::types::BufferOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BufferOptionsBuilder {
    pub(crate) persistent_buffer_enabled: ::std::option::Option<bool>,
}
impl BufferOptionsBuilder {
    /// <p>Whether persistent buffering should be enabled.</p>
    /// This field is required.
    pub fn persistent_buffer_enabled(mut self, input: bool) -> Self {
        self.persistent_buffer_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether persistent buffering should be enabled.</p>
    pub fn set_persistent_buffer_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.persistent_buffer_enabled = input;
        self
    }
    /// <p>Whether persistent buffering should be enabled.</p>
    pub fn get_persistent_buffer_enabled(&self) -> &::std::option::Option<bool> {
        &self.persistent_buffer_enabled
    }
    /// Consumes the builder and constructs a [`BufferOptions`](crate::types::BufferOptions).
    /// This method will fail if any of the following fields are not set:
    /// - [`persistent_buffer_enabled`](crate::types::builders::BufferOptionsBuilder::persistent_buffer_enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::BufferOptions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BufferOptions {
            persistent_buffer_enabled: self.persistent_buffer_enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "persistent_buffer_enabled",
                    "persistent_buffer_enabled was not specified but it is required when building BufferOptions",
                )
            })?,
        })
    }
}
