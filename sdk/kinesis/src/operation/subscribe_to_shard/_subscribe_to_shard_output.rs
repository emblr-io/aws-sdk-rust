// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::fmt::Debug)]
pub struct SubscribeToShardOutput {
    /// <p>The event stream that your consumer can use to read records from the shard.</p>
    #[cfg_attr(any(feature = "serde-serialize", feature = "serde-deserialize"), serde(skip))]
    pub event_stream:
        crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError>,
    _request_id: Option<String>,
}
impl SubscribeToShardOutput {
    /// <p>The event stream that your consumer can use to read records from the shard.</p>
    pub fn event_stream(
        &self,
    ) -> &crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError> {
        &self.event_stream
    }
}
impl ::aws_types::request_id::RequestId for SubscribeToShardOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SubscribeToShardOutput {
    /// Creates a new builder-style object to manufacture [`SubscribeToShardOutput`](crate::operation::subscribe_to_shard::SubscribeToShardOutput).
    pub fn builder() -> crate::operation::subscribe_to_shard::builders::SubscribeToShardOutputBuilder {
        crate::operation::subscribe_to_shard::builders::SubscribeToShardOutputBuilder::default()
    }
    #[allow(unused)]
    pub(crate) fn into_builder(self) -> crate::operation::subscribe_to_shard::builders::SubscribeToShardOutputBuilder {
        Self::builder().event_stream(self.event_stream)
    }
}

/// A builder for [`SubscribeToShardOutput`](crate::operation::subscribe_to_shard::SubscribeToShardOutput).
#[derive(::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubscribeToShardOutputBuilder {
    pub(crate) event_stream: ::std::option::Option<
        crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError>,
    >,
    _request_id: Option<String>,
}
impl SubscribeToShardOutputBuilder {
    /// <p>The event stream that your consumer can use to read records from the shard.</p>
    /// This field is required.
    pub fn event_stream(
        mut self,
        input: crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError>,
    ) -> Self {
        self.event_stream = ::std::option::Option::Some(input);
        self
    }
    /// <p>The event stream that your consumer can use to read records from the shard.</p>
    pub fn set_event_stream(
        mut self,
        input: ::std::option::Option<
            crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError>,
        >,
    ) -> Self {
        self.event_stream = input;
        self
    }
    /// <p>The event stream that your consumer can use to read records from the shard.</p>
    pub fn get_event_stream(
        &self,
    ) -> &::std::option::Option<
        crate::event_receiver::EventReceiver<crate::types::SubscribeToShardEventStream, crate::types::error::SubscribeToShardEventStreamError>,
    > {
        &self.event_stream
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SubscribeToShardOutput`](crate::operation::subscribe_to_shard::SubscribeToShardOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`event_stream`](crate::operation::subscribe_to_shard::builders::SubscribeToShardOutputBuilder::event_stream)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::subscribe_to_shard::SubscribeToShardOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::subscribe_to_shard::SubscribeToShardOutput {
            event_stream: self.event_stream.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_stream",
                    "event_stream was not specified but it is required when building SubscribeToShardOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
