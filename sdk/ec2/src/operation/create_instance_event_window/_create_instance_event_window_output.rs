// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateInstanceEventWindowOutput {
    /// <p>Information about the event window.</p>
    pub instance_event_window: ::std::option::Option<crate::types::InstanceEventWindow>,
    _request_id: Option<String>,
}
impl CreateInstanceEventWindowOutput {
    /// <p>Information about the event window.</p>
    pub fn instance_event_window(&self) -> ::std::option::Option<&crate::types::InstanceEventWindow> {
        self.instance_event_window.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateInstanceEventWindowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateInstanceEventWindowOutput {
    /// Creates a new builder-style object to manufacture [`CreateInstanceEventWindowOutput`](crate::operation::create_instance_event_window::CreateInstanceEventWindowOutput).
    pub fn builder() -> crate::operation::create_instance_event_window::builders::CreateInstanceEventWindowOutputBuilder {
        crate::operation::create_instance_event_window::builders::CreateInstanceEventWindowOutputBuilder::default()
    }
}

/// A builder for [`CreateInstanceEventWindowOutput`](crate::operation::create_instance_event_window::CreateInstanceEventWindowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateInstanceEventWindowOutputBuilder {
    pub(crate) instance_event_window: ::std::option::Option<crate::types::InstanceEventWindow>,
    _request_id: Option<String>,
}
impl CreateInstanceEventWindowOutputBuilder {
    /// <p>Information about the event window.</p>
    pub fn instance_event_window(mut self, input: crate::types::InstanceEventWindow) -> Self {
        self.instance_event_window = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the event window.</p>
    pub fn set_instance_event_window(mut self, input: ::std::option::Option<crate::types::InstanceEventWindow>) -> Self {
        self.instance_event_window = input;
        self
    }
    /// <p>Information about the event window.</p>
    pub fn get_instance_event_window(&self) -> &::std::option::Option<crate::types::InstanceEventWindow> {
        &self.instance_event_window
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateInstanceEventWindowOutput`](crate::operation::create_instance_event_window::CreateInstanceEventWindowOutput).
    pub fn build(self) -> crate::operation::create_instance_event_window::CreateInstanceEventWindowOutput {
        crate::operation::create_instance_event_window::CreateInstanceEventWindowOutput {
            instance_event_window: self.instance_event_window,
            _request_id: self._request_id,
        }
    }
}
