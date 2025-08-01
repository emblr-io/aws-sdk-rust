// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteThemeForStackOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteThemeForStackOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteThemeForStackOutput {
    /// Creates a new builder-style object to manufacture [`DeleteThemeForStackOutput`](crate::operation::delete_theme_for_stack::DeleteThemeForStackOutput).
    pub fn builder() -> crate::operation::delete_theme_for_stack::builders::DeleteThemeForStackOutputBuilder {
        crate::operation::delete_theme_for_stack::builders::DeleteThemeForStackOutputBuilder::default()
    }
}

/// A builder for [`DeleteThemeForStackOutput`](crate::operation::delete_theme_for_stack::DeleteThemeForStackOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteThemeForStackOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteThemeForStackOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteThemeForStackOutput`](crate::operation::delete_theme_for_stack::DeleteThemeForStackOutput).
    pub fn build(self) -> crate::operation::delete_theme_for_stack::DeleteThemeForStackOutput {
        crate::operation::delete_theme_for_stack::DeleteThemeForStackOutput {
            _request_id: self._request_id,
        }
    }
}
