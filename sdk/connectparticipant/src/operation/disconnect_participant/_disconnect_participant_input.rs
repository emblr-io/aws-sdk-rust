// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisconnectParticipantInput {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The authentication token associated with the participant's connection.</p>
    pub connection_token: ::std::option::Option<::std::string::String>,
}
impl DisconnectParticipantInput {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The authentication token associated with the participant's connection.</p>
    pub fn connection_token(&self) -> ::std::option::Option<&str> {
        self.connection_token.as_deref()
    }
}
impl DisconnectParticipantInput {
    /// Creates a new builder-style object to manufacture [`DisconnectParticipantInput`](crate::operation::disconnect_participant::DisconnectParticipantInput).
    pub fn builder() -> crate::operation::disconnect_participant::builders::DisconnectParticipantInputBuilder {
        crate::operation::disconnect_participant::builders::DisconnectParticipantInputBuilder::default()
    }
}

/// A builder for [`DisconnectParticipantInput`](crate::operation::disconnect_participant::DisconnectParticipantInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisconnectParticipantInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) connection_token: ::std::option::Option<::std::string::String>,
}
impl DisconnectParticipantInputBuilder {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The authentication token associated with the participant's connection.</p>
    /// This field is required.
    pub fn connection_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authentication token associated with the participant's connection.</p>
    pub fn set_connection_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_token = input;
        self
    }
    /// <p>The authentication token associated with the participant's connection.</p>
    pub fn get_connection_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_token
    }
    /// Consumes the builder and constructs a [`DisconnectParticipantInput`](crate::operation::disconnect_participant::DisconnectParticipantInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disconnect_participant::DisconnectParticipantInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::disconnect_participant::DisconnectParticipantInput {
            client_token: self.client_token,
            connection_token: self.connection_token,
        })
    }
}
