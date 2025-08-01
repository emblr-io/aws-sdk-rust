// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGuiSessionAccessDetailsInput {
    /// <p>The resource name.</p>
    pub resource_name: ::std::option::Option<::std::string::String>,
}
impl CreateGuiSessionAccessDetailsInput {
    /// <p>The resource name.</p>
    pub fn resource_name(&self) -> ::std::option::Option<&str> {
        self.resource_name.as_deref()
    }
}
impl CreateGuiSessionAccessDetailsInput {
    /// Creates a new builder-style object to manufacture [`CreateGuiSessionAccessDetailsInput`](crate::operation::create_gui_session_access_details::CreateGuiSessionAccessDetailsInput).
    pub fn builder() -> crate::operation::create_gui_session_access_details::builders::CreateGuiSessionAccessDetailsInputBuilder {
        crate::operation::create_gui_session_access_details::builders::CreateGuiSessionAccessDetailsInputBuilder::default()
    }
}

/// A builder for [`CreateGuiSessionAccessDetailsInput`](crate::operation::create_gui_session_access_details::CreateGuiSessionAccessDetailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGuiSessionAccessDetailsInputBuilder {
    pub(crate) resource_name: ::std::option::Option<::std::string::String>,
}
impl CreateGuiSessionAccessDetailsInputBuilder {
    /// <p>The resource name.</p>
    /// This field is required.
    pub fn resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource name.</p>
    pub fn set_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_name = input;
        self
    }
    /// <p>The resource name.</p>
    pub fn get_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_name
    }
    /// Consumes the builder and constructs a [`CreateGuiSessionAccessDetailsInput`](crate::operation::create_gui_session_access_details::CreateGuiSessionAccessDetailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_gui_session_access_details::CreateGuiSessionAccessDetailsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_gui_session_access_details::CreateGuiSessionAccessDetailsInput {
            resource_name: self.resource_name,
        })
    }
}
