// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProtocolsListInput {
    /// <p>The ID of the protocols list that you want to delete. You can retrieve this ID from <code>PutProtocolsList</code>, <code>ListProtocolsLists</code>, and <code>GetProtocolsLost</code>.</p>
    pub list_id: ::std::option::Option<::std::string::String>,
}
impl DeleteProtocolsListInput {
    /// <p>The ID of the protocols list that you want to delete. You can retrieve this ID from <code>PutProtocolsList</code>, <code>ListProtocolsLists</code>, and <code>GetProtocolsLost</code>.</p>
    pub fn list_id(&self) -> ::std::option::Option<&str> {
        self.list_id.as_deref()
    }
}
impl DeleteProtocolsListInput {
    /// Creates a new builder-style object to manufacture [`DeleteProtocolsListInput`](crate::operation::delete_protocols_list::DeleteProtocolsListInput).
    pub fn builder() -> crate::operation::delete_protocols_list::builders::DeleteProtocolsListInputBuilder {
        crate::operation::delete_protocols_list::builders::DeleteProtocolsListInputBuilder::default()
    }
}

/// A builder for [`DeleteProtocolsListInput`](crate::operation::delete_protocols_list::DeleteProtocolsListInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProtocolsListInputBuilder {
    pub(crate) list_id: ::std::option::Option<::std::string::String>,
}
impl DeleteProtocolsListInputBuilder {
    /// <p>The ID of the protocols list that you want to delete. You can retrieve this ID from <code>PutProtocolsList</code>, <code>ListProtocolsLists</code>, and <code>GetProtocolsLost</code>.</p>
    /// This field is required.
    pub fn list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the protocols list that you want to delete. You can retrieve this ID from <code>PutProtocolsList</code>, <code>ListProtocolsLists</code>, and <code>GetProtocolsLost</code>.</p>
    pub fn set_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.list_id = input;
        self
    }
    /// <p>The ID of the protocols list that you want to delete. You can retrieve this ID from <code>PutProtocolsList</code>, <code>ListProtocolsLists</code>, and <code>GetProtocolsLost</code>.</p>
    pub fn get_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.list_id
    }
    /// Consumes the builder and constructs a [`DeleteProtocolsListInput`](crate::operation::delete_protocols_list::DeleteProtocolsListInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_protocols_list::DeleteProtocolsListInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_protocols_list::DeleteProtocolsListInput { list_id: self.list_id })
    }
}
