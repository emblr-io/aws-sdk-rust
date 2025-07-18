// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DeregisterMemberFromAddressListInput {
    /// <p>The unique identifier of the address list to remove the address from.</p>
    pub address_list_id: ::std::option::Option<::std::string::String>,
    /// <p>The address to be removed from the address list.</p>
    pub address: ::std::option::Option<::std::string::String>,
}
impl DeregisterMemberFromAddressListInput {
    /// <p>The unique identifier of the address list to remove the address from.</p>
    pub fn address_list_id(&self) -> ::std::option::Option<&str> {
        self.address_list_id.as_deref()
    }
    /// <p>The address to be removed from the address list.</p>
    pub fn address(&self) -> ::std::option::Option<&str> {
        self.address.as_deref()
    }
}
impl ::std::fmt::Debug for DeregisterMemberFromAddressListInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeregisterMemberFromAddressListInput");
        formatter.field("address_list_id", &self.address_list_id);
        formatter.field("address", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl DeregisterMemberFromAddressListInput {
    /// Creates a new builder-style object to manufacture [`DeregisterMemberFromAddressListInput`](crate::operation::deregister_member_from_address_list::DeregisterMemberFromAddressListInput).
    pub fn builder() -> crate::operation::deregister_member_from_address_list::builders::DeregisterMemberFromAddressListInputBuilder {
        crate::operation::deregister_member_from_address_list::builders::DeregisterMemberFromAddressListInputBuilder::default()
    }
}

/// A builder for [`DeregisterMemberFromAddressListInput`](crate::operation::deregister_member_from_address_list::DeregisterMemberFromAddressListInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeregisterMemberFromAddressListInputBuilder {
    pub(crate) address_list_id: ::std::option::Option<::std::string::String>,
    pub(crate) address: ::std::option::Option<::std::string::String>,
}
impl DeregisterMemberFromAddressListInputBuilder {
    /// <p>The unique identifier of the address list to remove the address from.</p>
    /// This field is required.
    pub fn address_list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the address list to remove the address from.</p>
    pub fn set_address_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_list_id = input;
        self
    }
    /// <p>The unique identifier of the address list to remove the address from.</p>
    pub fn get_address_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_list_id
    }
    /// <p>The address to be removed from the address list.</p>
    /// This field is required.
    pub fn address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address to be removed from the address list.</p>
    pub fn set_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address = input;
        self
    }
    /// <p>The address to be removed from the address list.</p>
    pub fn get_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.address
    }
    /// Consumes the builder and constructs a [`DeregisterMemberFromAddressListInput`](crate::operation::deregister_member_from_address_list::DeregisterMemberFromAddressListInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::deregister_member_from_address_list::DeregisterMemberFromAddressListInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::deregister_member_from_address_list::DeregisterMemberFromAddressListInput {
                address_list_id: self.address_list_id,
                address: self.address,
            },
        )
    }
}
impl ::std::fmt::Debug for DeregisterMemberFromAddressListInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeregisterMemberFromAddressListInputBuilder");
        formatter.field("address_list_id", &self.address_list_id);
        formatter.field("address", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
