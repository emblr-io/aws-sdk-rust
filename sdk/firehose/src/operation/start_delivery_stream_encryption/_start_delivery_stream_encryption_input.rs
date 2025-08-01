// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDeliveryStreamEncryptionInput {
    /// <p>The name of the Firehose stream for which you want to enable server-side encryption (SSE).</p>
    pub delivery_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>Used to specify the type and Amazon Resource Name (ARN) of the KMS key needed for Server-Side Encryption (SSE).</p>
    pub delivery_stream_encryption_configuration_input: ::std::option::Option<crate::types::DeliveryStreamEncryptionConfigurationInput>,
}
impl StartDeliveryStreamEncryptionInput {
    /// <p>The name of the Firehose stream for which you want to enable server-side encryption (SSE).</p>
    pub fn delivery_stream_name(&self) -> ::std::option::Option<&str> {
        self.delivery_stream_name.as_deref()
    }
    /// <p>Used to specify the type and Amazon Resource Name (ARN) of the KMS key needed for Server-Side Encryption (SSE).</p>
    pub fn delivery_stream_encryption_configuration_input(&self) -> ::std::option::Option<&crate::types::DeliveryStreamEncryptionConfigurationInput> {
        self.delivery_stream_encryption_configuration_input.as_ref()
    }
}
impl StartDeliveryStreamEncryptionInput {
    /// Creates a new builder-style object to manufacture [`StartDeliveryStreamEncryptionInput`](crate::operation::start_delivery_stream_encryption::StartDeliveryStreamEncryptionInput).
    pub fn builder() -> crate::operation::start_delivery_stream_encryption::builders::StartDeliveryStreamEncryptionInputBuilder {
        crate::operation::start_delivery_stream_encryption::builders::StartDeliveryStreamEncryptionInputBuilder::default()
    }
}

/// A builder for [`StartDeliveryStreamEncryptionInput`](crate::operation::start_delivery_stream_encryption::StartDeliveryStreamEncryptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDeliveryStreamEncryptionInputBuilder {
    pub(crate) delivery_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) delivery_stream_encryption_configuration_input: ::std::option::Option<crate::types::DeliveryStreamEncryptionConfigurationInput>,
}
impl StartDeliveryStreamEncryptionInputBuilder {
    /// <p>The name of the Firehose stream for which you want to enable server-side encryption (SSE).</p>
    /// This field is required.
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Firehose stream for which you want to enable server-side encryption (SSE).</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream_name = input;
        self
    }
    /// <p>The name of the Firehose stream for which you want to enable server-side encryption (SSE).</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream_name
    }
    /// <p>Used to specify the type and Amazon Resource Name (ARN) of the KMS key needed for Server-Side Encryption (SSE).</p>
    pub fn delivery_stream_encryption_configuration_input(mut self, input: crate::types::DeliveryStreamEncryptionConfigurationInput) -> Self {
        self.delivery_stream_encryption_configuration_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Used to specify the type and Amazon Resource Name (ARN) of the KMS key needed for Server-Side Encryption (SSE).</p>
    pub fn set_delivery_stream_encryption_configuration_input(
        mut self,
        input: ::std::option::Option<crate::types::DeliveryStreamEncryptionConfigurationInput>,
    ) -> Self {
        self.delivery_stream_encryption_configuration_input = input;
        self
    }
    /// <p>Used to specify the type and Amazon Resource Name (ARN) of the KMS key needed for Server-Side Encryption (SSE).</p>
    pub fn get_delivery_stream_encryption_configuration_input(
        &self,
    ) -> &::std::option::Option<crate::types::DeliveryStreamEncryptionConfigurationInput> {
        &self.delivery_stream_encryption_configuration_input
    }
    /// Consumes the builder and constructs a [`StartDeliveryStreamEncryptionInput`](crate::operation::start_delivery_stream_encryption::StartDeliveryStreamEncryptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_delivery_stream_encryption::StartDeliveryStreamEncryptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_delivery_stream_encryption::StartDeliveryStreamEncryptionInput {
            delivery_stream_name: self.delivery_stream_name,
            delivery_stream_encryption_configuration_input: self.delivery_stream_encryption_configuration_input,
        })
    }
}
