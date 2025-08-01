// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAddressListInput {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>A user-friendly name for the address list.</p>
    pub address_list_name: ::std::option::Option<::std::string::String>,
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAddressListInput {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>A user-friendly name for the address list.</p>
    pub fn address_list_name(&self) -> ::std::option::Option<&str> {
        self.address_list_name.as_deref()
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateAddressListInput {
    /// Creates a new builder-style object to manufacture [`CreateAddressListInput`](crate::operation::create_address_list::CreateAddressListInput).
    pub fn builder() -> crate::operation::create_address_list::builders::CreateAddressListInputBuilder {
        crate::operation::create_address_list::builders::CreateAddressListInputBuilder::default()
    }
}

/// A builder for [`CreateAddressListInput`](crate::operation::create_address_list::CreateAddressListInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAddressListInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) address_list_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAddressListInputBuilder {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>A user-friendly name for the address list.</p>
    /// This field is required.
    pub fn address_list_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_list_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-friendly name for the address list.</p>
    pub fn set_address_list_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_list_name = input;
        self
    }
    /// <p>A user-friendly name for the address list.</p>
    pub fn get_address_list_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_list_name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateAddressListInput`](crate::operation::create_address_list::CreateAddressListInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_address_list::CreateAddressListInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_address_list::CreateAddressListInput {
            client_token: self.client_token,
            address_list_name: self.address_list_name,
            tags: self.tags,
        })
    }
}
