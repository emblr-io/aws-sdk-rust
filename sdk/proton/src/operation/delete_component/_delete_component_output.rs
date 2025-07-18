// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteComponentOutput {
    /// <p>The detailed data of the component being deleted.</p>
    pub component: ::std::option::Option<crate::types::Component>,
    _request_id: Option<String>,
}
impl DeleteComponentOutput {
    /// <p>The detailed data of the component being deleted.</p>
    pub fn component(&self) -> ::std::option::Option<&crate::types::Component> {
        self.component.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteComponentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteComponentOutput {
    /// Creates a new builder-style object to manufacture [`DeleteComponentOutput`](crate::operation::delete_component::DeleteComponentOutput).
    pub fn builder() -> crate::operation::delete_component::builders::DeleteComponentOutputBuilder {
        crate::operation::delete_component::builders::DeleteComponentOutputBuilder::default()
    }
}

/// A builder for [`DeleteComponentOutput`](crate::operation::delete_component::DeleteComponentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteComponentOutputBuilder {
    pub(crate) component: ::std::option::Option<crate::types::Component>,
    _request_id: Option<String>,
}
impl DeleteComponentOutputBuilder {
    /// <p>The detailed data of the component being deleted.</p>
    pub fn component(mut self, input: crate::types::Component) -> Self {
        self.component = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detailed data of the component being deleted.</p>
    pub fn set_component(mut self, input: ::std::option::Option<crate::types::Component>) -> Self {
        self.component = input;
        self
    }
    /// <p>The detailed data of the component being deleted.</p>
    pub fn get_component(&self) -> &::std::option::Option<crate::types::Component> {
        &self.component
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteComponentOutput`](crate::operation::delete_component::DeleteComponentOutput).
    pub fn build(self) -> crate::operation::delete_component::DeleteComponentOutput {
        crate::operation::delete_component::DeleteComponentOutput {
            component: self.component,
            _request_id: self._request_id,
        }
    }
}
