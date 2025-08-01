// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies one or more sets of channel messages.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelMessages {
    /// <p>Specifies one or more keys that identify the Amazon Simple Storage Service (Amazon S3) objects that save your channel messages.</p>
    /// <p>You must use the full path for the key.</p>
    /// <p>Example path: <code>channel/mychannel/__dt=2020-02-29 00:00:00/1582940490000_1582940520000_123456789012_mychannel_0_2118.0.json.gz</code></p>
    pub s3_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ChannelMessages {
    /// <p>Specifies one or more keys that identify the Amazon Simple Storage Service (Amazon S3) objects that save your channel messages.</p>
    /// <p>You must use the full path for the key.</p>
    /// <p>Example path: <code>channel/mychannel/__dt=2020-02-29 00:00:00/1582940490000_1582940520000_123456789012_mychannel_0_2118.0.json.gz</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.s3_paths.is_none()`.
    pub fn s3_paths(&self) -> &[::std::string::String] {
        self.s3_paths.as_deref().unwrap_or_default()
    }
}
impl ChannelMessages {
    /// Creates a new builder-style object to manufacture [`ChannelMessages`](crate::types::ChannelMessages).
    pub fn builder() -> crate::types::builders::ChannelMessagesBuilder {
        crate::types::builders::ChannelMessagesBuilder::default()
    }
}

/// A builder for [`ChannelMessages`](crate::types::ChannelMessages).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelMessagesBuilder {
    pub(crate) s3_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ChannelMessagesBuilder {
    /// Appends an item to `s3_paths`.
    ///
    /// To override the contents of this collection use [`set_s3_paths`](Self::set_s3_paths).
    ///
    /// <p>Specifies one or more keys that identify the Amazon Simple Storage Service (Amazon S3) objects that save your channel messages.</p>
    /// <p>You must use the full path for the key.</p>
    /// <p>Example path: <code>channel/mychannel/__dt=2020-02-29 00:00:00/1582940490000_1582940520000_123456789012_mychannel_0_2118.0.json.gz</code></p>
    pub fn s3_paths(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.s3_paths.unwrap_or_default();
        v.push(input.into());
        self.s3_paths = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies one or more keys that identify the Amazon Simple Storage Service (Amazon S3) objects that save your channel messages.</p>
    /// <p>You must use the full path for the key.</p>
    /// <p>Example path: <code>channel/mychannel/__dt=2020-02-29 00:00:00/1582940490000_1582940520000_123456789012_mychannel_0_2118.0.json.gz</code></p>
    pub fn set_s3_paths(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.s3_paths = input;
        self
    }
    /// <p>Specifies one or more keys that identify the Amazon Simple Storage Service (Amazon S3) objects that save your channel messages.</p>
    /// <p>You must use the full path for the key.</p>
    /// <p>Example path: <code>channel/mychannel/__dt=2020-02-29 00:00:00/1582940490000_1582940520000_123456789012_mychannel_0_2118.0.json.gz</code></p>
    pub fn get_s3_paths(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.s3_paths
    }
    /// Consumes the builder and constructs a [`ChannelMessages`](crate::types::ChannelMessages).
    pub fn build(self) -> crate::types::ChannelMessages {
        crate::types::ChannelMessages { s3_paths: self.s3_paths }
    }
}
