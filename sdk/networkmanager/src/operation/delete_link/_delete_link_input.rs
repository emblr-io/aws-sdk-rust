// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLinkInput {
    /// <p>The ID of the global network.</p>
    pub global_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the link.</p>
    pub link_id: ::std::option::Option<::std::string::String>,
}
impl DeleteLinkInput {
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(&self) -> ::std::option::Option<&str> {
        self.global_network_id.as_deref()
    }
    /// <p>The ID of the link.</p>
    pub fn link_id(&self) -> ::std::option::Option<&str> {
        self.link_id.as_deref()
    }
}
impl DeleteLinkInput {
    /// Creates a new builder-style object to manufacture [`DeleteLinkInput`](crate::operation::delete_link::DeleteLinkInput).
    pub fn builder() -> crate::operation::delete_link::builders::DeleteLinkInputBuilder {
        crate::operation::delete_link::builders::DeleteLinkInputBuilder::default()
    }
}

/// A builder for [`DeleteLinkInput`](crate::operation::delete_link::DeleteLinkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLinkInputBuilder {
    pub(crate) global_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) link_id: ::std::option::Option<::std::string::String>,
}
impl DeleteLinkInputBuilder {
    /// <p>The ID of the global network.</p>
    /// This field is required.
    pub fn global_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn set_global_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_network_id = input;
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn get_global_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_network_id
    }
    /// <p>The ID of the link.</p>
    /// This field is required.
    pub fn link_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.link_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the link.</p>
    pub fn set_link_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.link_id = input;
        self
    }
    /// <p>The ID of the link.</p>
    pub fn get_link_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.link_id
    }
    /// Consumes the builder and constructs a [`DeleteLinkInput`](crate::operation::delete_link::DeleteLinkInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_link::DeleteLinkInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_link::DeleteLinkInput {
            global_network_id: self.global_network_id,
            link_id: self.link_id,
        })
    }
}
