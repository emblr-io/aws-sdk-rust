// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::create_email_address::_create_email_address_output::CreateEmailAddressOutputBuilder;

pub use crate::operation::create_email_address::_create_email_address_input::CreateEmailAddressInputBuilder;

impl crate::operation::create_email_address::builders::CreateEmailAddressInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::create_email_address::CreateEmailAddressOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::create_email_address::CreateEmailAddressError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.create_email_address();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `CreateEmailAddress`.
///
/// <p>Create new email address in the specified Amazon Connect instance. For more information about email addresses, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/create-email-address1.html">Create email addresses</a> in the Amazon Connect Administrator Guide.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct CreateEmailAddressFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::create_email_address::builders::CreateEmailAddressInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::create_email_address::CreateEmailAddressOutput,
        crate::operation::create_email_address::CreateEmailAddressError,
    > for CreateEmailAddressFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::create_email_address::CreateEmailAddressOutput,
            crate::operation::create_email_address::CreateEmailAddressError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl CreateEmailAddressFluentBuilder {
    /// Creates a new `CreateEmailAddressFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the CreateEmailAddress as a reference.
    pub fn as_input(&self) -> &crate::operation::create_email_address::builders::CreateEmailAddressInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_email_address::CreateEmailAddressOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::create_email_address::CreateEmailAddressError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::create_email_address::CreateEmailAddress::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::create_email_address::CreateEmailAddress::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::create_email_address::CreateEmailAddressOutput,
        crate::operation::create_email_address::CreateEmailAddressError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The description of the email address.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.description(input.into());
        self
    }
    /// <p>The description of the email address.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_description(input);
        self
    }
    /// <p>The description of the email address.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_description()
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.instance_id(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_instance_id(input);
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_instance_id()
    }
    /// <p>The email address, including the domain.</p>
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.email_address(input.into());
        self
    }
    /// <p>The email address, including the domain.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_email_address(input);
        self
    }
    /// <p>The email address, including the domain.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_email_address()
    }
    /// <p>The display name of email address</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.display_name(input.into());
        self
    }
    /// <p>The display name of email address</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_display_name(input);
        self
    }
    /// <p>The display name of email address</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_display_name()
    }
    ///
    /// Adds a key-value pair to `Tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.tags(k.into(), v.into());
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.inner = self.inner.set_tags(input);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.inner.get_tags()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.client_token(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_client_token(input);
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_client_token()
    }
}
