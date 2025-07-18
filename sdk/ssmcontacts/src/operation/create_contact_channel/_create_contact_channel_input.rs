// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateContactChannelInput {
    /// <p>The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.</p>
    pub contact_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the contact channel.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Incident Manager supports three types of contact channels:</p>
    /// <ul>
    /// <li>
    /// <p><code>SMS</code></p></li>
    /// <li>
    /// <p><code>VOICE</code></p></li>
    /// <li>
    /// <p><code>EMAIL</code></p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::ChannelType>,
    /// <p>The details that Incident Manager uses when trying to engage the contact channel. The format is dependent on the type of the contact channel. The following are the expected formats:</p>
    /// <ul>
    /// <li>
    /// <p>SMS - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>VOICE - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>EMAIL - any standard email format</p></li>
    /// </ul>
    pub delivery_address: ::std::option::Option<crate::types::ContactChannelAddress>,
    /// <p>If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.</p>
    pub defer_activation: ::std::option::Option<bool>,
    /// <p>A token ensuring that the operation is called only once with the specified details.</p>
    pub idempotency_token: ::std::option::Option<::std::string::String>,
}
impl CreateContactChannelInput {
    /// <p>The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.</p>
    pub fn contact_id(&self) -> ::std::option::Option<&str> {
        self.contact_id.as_deref()
    }
    /// <p>The name of the contact channel.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Incident Manager supports three types of contact channels:</p>
    /// <ul>
    /// <li>
    /// <p><code>SMS</code></p></li>
    /// <li>
    /// <p><code>VOICE</code></p></li>
    /// <li>
    /// <p><code>EMAIL</code></p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ChannelType> {
        self.r#type.as_ref()
    }
    /// <p>The details that Incident Manager uses when trying to engage the contact channel. The format is dependent on the type of the contact channel. The following are the expected formats:</p>
    /// <ul>
    /// <li>
    /// <p>SMS - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>VOICE - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>EMAIL - any standard email format</p></li>
    /// </ul>
    pub fn delivery_address(&self) -> ::std::option::Option<&crate::types::ContactChannelAddress> {
        self.delivery_address.as_ref()
    }
    /// <p>If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.</p>
    pub fn defer_activation(&self) -> ::std::option::Option<bool> {
        self.defer_activation
    }
    /// <p>A token ensuring that the operation is called only once with the specified details.</p>
    pub fn idempotency_token(&self) -> ::std::option::Option<&str> {
        self.idempotency_token.as_deref()
    }
}
impl CreateContactChannelInput {
    /// Creates a new builder-style object to manufacture [`CreateContactChannelInput`](crate::operation::create_contact_channel::CreateContactChannelInput).
    pub fn builder() -> crate::operation::create_contact_channel::builders::CreateContactChannelInputBuilder {
        crate::operation::create_contact_channel::builders::CreateContactChannelInputBuilder::default()
    }
}

/// A builder for [`CreateContactChannelInput`](crate::operation::create_contact_channel::CreateContactChannelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateContactChannelInputBuilder {
    pub(crate) contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ChannelType>,
    pub(crate) delivery_address: ::std::option::Option<crate::types::ContactChannelAddress>,
    pub(crate) defer_activation: ::std::option::Option<bool>,
    pub(crate) idempotency_token: ::std::option::Option<::std::string::String>,
}
impl CreateContactChannelInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.</p>
    /// This field is required.
    pub fn contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.</p>
    pub fn set_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.</p>
    pub fn get_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_id
    }
    /// <p>The name of the contact channel.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the contact channel.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the contact channel.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Incident Manager supports three types of contact channels:</p>
    /// <ul>
    /// <li>
    /// <p><code>SMS</code></p></li>
    /// <li>
    /// <p><code>VOICE</code></p></li>
    /// <li>
    /// <p><code>EMAIL</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ChannelType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Incident Manager supports three types of contact channels:</p>
    /// <ul>
    /// <li>
    /// <p><code>SMS</code></p></li>
    /// <li>
    /// <p><code>VOICE</code></p></li>
    /// <li>
    /// <p><code>EMAIL</code></p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ChannelType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Incident Manager supports three types of contact channels:</p>
    /// <ul>
    /// <li>
    /// <p><code>SMS</code></p></li>
    /// <li>
    /// <p><code>VOICE</code></p></li>
    /// <li>
    /// <p><code>EMAIL</code></p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ChannelType> {
        &self.r#type
    }
    /// <p>The details that Incident Manager uses when trying to engage the contact channel. The format is dependent on the type of the contact channel. The following are the expected formats:</p>
    /// <ul>
    /// <li>
    /// <p>SMS - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>VOICE - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>EMAIL - any standard email format</p></li>
    /// </ul>
    /// This field is required.
    pub fn delivery_address(mut self, input: crate::types::ContactChannelAddress) -> Self {
        self.delivery_address = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details that Incident Manager uses when trying to engage the contact channel. The format is dependent on the type of the contact channel. The following are the expected formats:</p>
    /// <ul>
    /// <li>
    /// <p>SMS - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>VOICE - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>EMAIL - any standard email format</p></li>
    /// </ul>
    pub fn set_delivery_address(mut self, input: ::std::option::Option<crate::types::ContactChannelAddress>) -> Self {
        self.delivery_address = input;
        self
    }
    /// <p>The details that Incident Manager uses when trying to engage the contact channel. The format is dependent on the type of the contact channel. The following are the expected formats:</p>
    /// <ul>
    /// <li>
    /// <p>SMS - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>VOICE - '+' followed by the country code and phone number</p></li>
    /// <li>
    /// <p>EMAIL - any standard email format</p></li>
    /// </ul>
    pub fn get_delivery_address(&self) -> &::std::option::Option<crate::types::ContactChannelAddress> {
        &self.delivery_address
    }
    /// <p>If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.</p>
    pub fn defer_activation(mut self, input: bool) -> Self {
        self.defer_activation = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.</p>
    pub fn set_defer_activation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.defer_activation = input;
        self
    }
    /// <p>If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.</p>
    pub fn get_defer_activation(&self) -> &::std::option::Option<bool> {
        &self.defer_activation
    }
    /// <p>A token ensuring that the operation is called only once with the specified details.</p>
    pub fn idempotency_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idempotency_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token ensuring that the operation is called only once with the specified details.</p>
    pub fn set_idempotency_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idempotency_token = input;
        self
    }
    /// <p>A token ensuring that the operation is called only once with the specified details.</p>
    pub fn get_idempotency_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.idempotency_token
    }
    /// Consumes the builder and constructs a [`CreateContactChannelInput`](crate::operation::create_contact_channel::CreateContactChannelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_contact_channel::CreateContactChannelInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_contact_channel::CreateContactChannelInput {
            contact_id: self.contact_id,
            name: self.name,
            r#type: self.r#type,
            delivery_address: self.delivery_address,
            defer_activation: self.defer_activation,
            idempotency_token: self.idempotency_token,
        })
    }
}
