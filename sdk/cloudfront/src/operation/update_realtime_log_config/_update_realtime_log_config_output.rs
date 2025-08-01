// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRealtimeLogConfigOutput {
    /// <p>A real-time log configuration.</p>
    pub realtime_log_config: ::std::option::Option<crate::types::RealtimeLogConfig>,
    _request_id: Option<String>,
}
impl UpdateRealtimeLogConfigOutput {
    /// <p>A real-time log configuration.</p>
    pub fn realtime_log_config(&self) -> ::std::option::Option<&crate::types::RealtimeLogConfig> {
        self.realtime_log_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateRealtimeLogConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateRealtimeLogConfigOutput {
    /// Creates a new builder-style object to manufacture [`UpdateRealtimeLogConfigOutput`](crate::operation::update_realtime_log_config::UpdateRealtimeLogConfigOutput).
    pub fn builder() -> crate::operation::update_realtime_log_config::builders::UpdateRealtimeLogConfigOutputBuilder {
        crate::operation::update_realtime_log_config::builders::UpdateRealtimeLogConfigOutputBuilder::default()
    }
}

/// A builder for [`UpdateRealtimeLogConfigOutput`](crate::operation::update_realtime_log_config::UpdateRealtimeLogConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRealtimeLogConfigOutputBuilder {
    pub(crate) realtime_log_config: ::std::option::Option<crate::types::RealtimeLogConfig>,
    _request_id: Option<String>,
}
impl UpdateRealtimeLogConfigOutputBuilder {
    /// <p>A real-time log configuration.</p>
    pub fn realtime_log_config(mut self, input: crate::types::RealtimeLogConfig) -> Self {
        self.realtime_log_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A real-time log configuration.</p>
    pub fn set_realtime_log_config(mut self, input: ::std::option::Option<crate::types::RealtimeLogConfig>) -> Self {
        self.realtime_log_config = input;
        self
    }
    /// <p>A real-time log configuration.</p>
    pub fn get_realtime_log_config(&self) -> &::std::option::Option<crate::types::RealtimeLogConfig> {
        &self.realtime_log_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateRealtimeLogConfigOutput`](crate::operation::update_realtime_log_config::UpdateRealtimeLogConfigOutput).
    pub fn build(self) -> crate::operation::update_realtime_log_config::UpdateRealtimeLogConfigOutput {
        crate::operation::update_realtime_log_config::UpdateRealtimeLogConfigOutput {
            realtime_log_config: self.realtime_log_config,
            _request_id: self._request_id,
        }
    }
}
