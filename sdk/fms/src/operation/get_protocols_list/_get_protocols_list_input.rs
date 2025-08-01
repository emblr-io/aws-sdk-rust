// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProtocolsListInput {
    /// <p>The ID of the Firewall Manager protocols list that you want the details for.</p>
    pub list_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the list to retrieve is a default list owned by Firewall Manager.</p>
    pub default_list: ::std::option::Option<bool>,
}
impl GetProtocolsListInput {
    /// <p>The ID of the Firewall Manager protocols list that you want the details for.</p>
    pub fn list_id(&self) -> ::std::option::Option<&str> {
        self.list_id.as_deref()
    }
    /// <p>Specifies whether the list to retrieve is a default list owned by Firewall Manager.</p>
    pub fn default_list(&self) -> ::std::option::Option<bool> {
        self.default_list
    }
}
impl GetProtocolsListInput {
    /// Creates a new builder-style object to manufacture [`GetProtocolsListInput`](crate::operation::get_protocols_list::GetProtocolsListInput).
    pub fn builder() -> crate::operation::get_protocols_list::builders::GetProtocolsListInputBuilder {
        crate::operation::get_protocols_list::builders::GetProtocolsListInputBuilder::default()
    }
}

/// A builder for [`GetProtocolsListInput`](crate::operation::get_protocols_list::GetProtocolsListInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProtocolsListInputBuilder {
    pub(crate) list_id: ::std::option::Option<::std::string::String>,
    pub(crate) default_list: ::std::option::Option<bool>,
}
impl GetProtocolsListInputBuilder {
    /// <p>The ID of the Firewall Manager protocols list that you want the details for.</p>
    /// This field is required.
    pub fn list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Firewall Manager protocols list that you want the details for.</p>
    pub fn set_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.list_id = input;
        self
    }
    /// <p>The ID of the Firewall Manager protocols list that you want the details for.</p>
    pub fn get_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.list_id
    }
    /// <p>Specifies whether the list to retrieve is a default list owned by Firewall Manager.</p>
    pub fn default_list(mut self, input: bool) -> Self {
        self.default_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the list to retrieve is a default list owned by Firewall Manager.</p>
    pub fn set_default_list(mut self, input: ::std::option::Option<bool>) -> Self {
        self.default_list = input;
        self
    }
    /// <p>Specifies whether the list to retrieve is a default list owned by Firewall Manager.</p>
    pub fn get_default_list(&self) -> &::std::option::Option<bool> {
        &self.default_list
    }
    /// Consumes the builder and constructs a [`GetProtocolsListInput`](crate::operation::get_protocols_list::GetProtocolsListInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_protocols_list::GetProtocolsListInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_protocols_list::GetProtocolsListInput {
            list_id: self.list_id,
            default_list: self.default_list,
        })
    }
}
