// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateChannelFlowInput {
    /// <p>The ARN of the channel flow request.</p>
    pub app_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>Information about the processor Lambda functions.</p>
    pub processors: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>,
    /// <p>The name of the channel flow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The tags for the creation request.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The client token for the request. An Idempotency token.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateChannelFlowInput {
    /// <p>The ARN of the channel flow request.</p>
    pub fn app_instance_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_arn.as_deref()
    }
    /// <p>Information about the processor Lambda functions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.processors.is_none()`.
    pub fn processors(&self) -> &[crate::types::Processor] {
        self.processors.as_deref().unwrap_or_default()
    }
    /// <p>The name of the channel flow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The tags for the creation request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The client token for the request. An Idempotency token.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateChannelFlowInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateChannelFlowInput");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("processors", &self.processors);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.field("client_request_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateChannelFlowInput {
    /// Creates a new builder-style object to manufacture [`CreateChannelFlowInput`](crate::operation::create_channel_flow::CreateChannelFlowInput).
    pub fn builder() -> crate::operation::create_channel_flow::builders::CreateChannelFlowInputBuilder {
        crate::operation::create_channel_flow::builders::CreateChannelFlowInputBuilder::default()
    }
}

/// A builder for [`CreateChannelFlowInput`](crate::operation::create_channel_flow::CreateChannelFlowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateChannelFlowInputBuilder {
    pub(crate) app_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) processors: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateChannelFlowInputBuilder {
    /// <p>The ARN of the channel flow request.</p>
    /// This field is required.
    pub fn app_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel flow request.</p>
    pub fn set_app_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_arn = input;
        self
    }
    /// <p>The ARN of the channel flow request.</p>
    pub fn get_app_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_arn
    }
    /// Appends an item to `processors`.
    ///
    /// To override the contents of this collection use [`set_processors`](Self::set_processors).
    ///
    /// <p>Information about the processor Lambda functions.</p>
    pub fn processors(mut self, input: crate::types::Processor) -> Self {
        let mut v = self.processors.unwrap_or_default();
        v.push(input);
        self.processors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the processor Lambda functions.</p>
    pub fn set_processors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>) -> Self {
        self.processors = input;
        self
    }
    /// <p>Information about the processor Lambda functions.</p>
    pub fn get_processors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Processor>> {
        &self.processors
    }
    /// <p>The name of the channel flow.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel flow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the channel flow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the creation request.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags for the creation request.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the creation request.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The client token for the request. An Idempotency token.</p>
    /// This field is required.
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client token for the request. An Idempotency token.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>The client token for the request. An Idempotency token.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`CreateChannelFlowInput`](crate::operation::create_channel_flow::CreateChannelFlowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_channel_flow::CreateChannelFlowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_channel_flow::CreateChannelFlowInput {
            app_instance_arn: self.app_instance_arn,
            processors: self.processors,
            name: self.name,
            tags: self.tags,
            client_request_token: self.client_request_token,
        })
    }
}
impl ::std::fmt::Debug for CreateChannelFlowInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateChannelFlowInputBuilder");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("processors", &self.processors);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.field("client_request_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
