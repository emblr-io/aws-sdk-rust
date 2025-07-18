// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVerifiedDestinationNumberInput {
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub destination_phone_number: ::std::option::Option<::std::string::String>,
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don't specify a client token, a randomly generated token is used for the request to ensure idempotency.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateVerifiedDestinationNumberInput {
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn destination_phone_number(&self) -> ::std::option::Option<&str> {
        self.destination_phone_number.as_deref()
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don't specify a client token, a randomly generated token is used for the request to ensure idempotency.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateVerifiedDestinationNumberInput {
    /// Creates a new builder-style object to manufacture [`CreateVerifiedDestinationNumberInput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberInput).
    pub fn builder() -> crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberInputBuilder {
        crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberInputBuilder::default()
    }
}

/// A builder for [`CreateVerifiedDestinationNumberInput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVerifiedDestinationNumberInputBuilder {
    pub(crate) destination_phone_number: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateVerifiedDestinationNumberInputBuilder {
    /// <p>The verified destination phone number, in E.164 format.</p>
    /// This field is required.
    pub fn destination_phone_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_phone_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn set_destination_phone_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_phone_number = input;
        self
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn get_destination_phone_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_phone_number
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don't specify a client token, a randomly generated token is used for the request to ensure idempotency.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don't specify a client token, a randomly generated token is used for the request to ensure idempotency.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don't specify a client token, a randomly generated token is used for the request to ensure idempotency.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateVerifiedDestinationNumberInput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberInput {
                destination_phone_number: self.destination_phone_number,
                tags: self.tags,
                client_token: self.client_token,
            },
        )
    }
}
