// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartGuiSessionOutput {
    /// <p>The available API operations.</p>
    pub operations: ::std::option::Option<::std::vec::Vec<crate::types::Operation>>,
    _request_id: Option<String>,
}
impl StartGuiSessionOutput {
    /// <p>The available API operations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.operations.is_none()`.
    pub fn operations(&self) -> &[crate::types::Operation] {
        self.operations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for StartGuiSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartGuiSessionOutput {
    /// Creates a new builder-style object to manufacture [`StartGuiSessionOutput`](crate::operation::start_gui_session::StartGuiSessionOutput).
    pub fn builder() -> crate::operation::start_gui_session::builders::StartGuiSessionOutputBuilder {
        crate::operation::start_gui_session::builders::StartGuiSessionOutputBuilder::default()
    }
}

/// A builder for [`StartGuiSessionOutput`](crate::operation::start_gui_session::StartGuiSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartGuiSessionOutputBuilder {
    pub(crate) operations: ::std::option::Option<::std::vec::Vec<crate::types::Operation>>,
    _request_id: Option<String>,
}
impl StartGuiSessionOutputBuilder {
    /// Appends an item to `operations`.
    ///
    /// To override the contents of this collection use [`set_operations`](Self::set_operations).
    ///
    /// <p>The available API operations.</p>
    pub fn operations(mut self, input: crate::types::Operation) -> Self {
        let mut v = self.operations.unwrap_or_default();
        v.push(input);
        self.operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The available API operations.</p>
    pub fn set_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Operation>>) -> Self {
        self.operations = input;
        self
    }
    /// <p>The available API operations.</p>
    pub fn get_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Operation>> {
        &self.operations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartGuiSessionOutput`](crate::operation::start_gui_session::StartGuiSessionOutput).
    pub fn build(self) -> crate::operation::start_gui_session::StartGuiSessionOutput {
        crate::operation::start_gui_session::StartGuiSessionOutput {
            operations: self.operations,
            _request_id: self._request_id,
        }
    }
}
