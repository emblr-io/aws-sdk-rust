// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBotOutput {
    /// <p>The bot details.</p>
    pub bot: ::std::option::Option<crate::types::Bot>,
    _request_id: Option<String>,
}
impl CreateBotOutput {
    /// <p>The bot details.</p>
    pub fn bot(&self) -> ::std::option::Option<&crate::types::Bot> {
        self.bot.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBotOutput {
    /// Creates a new builder-style object to manufacture [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
    pub fn builder() -> crate::operation::create_bot::builders::CreateBotOutputBuilder {
        crate::operation::create_bot::builders::CreateBotOutputBuilder::default()
    }
}

/// A builder for [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBotOutputBuilder {
    pub(crate) bot: ::std::option::Option<crate::types::Bot>,
    _request_id: Option<String>,
}
impl CreateBotOutputBuilder {
    /// <p>The bot details.</p>
    pub fn bot(mut self, input: crate::types::Bot) -> Self {
        self.bot = ::std::option::Option::Some(input);
        self
    }
    /// <p>The bot details.</p>
    pub fn set_bot(mut self, input: ::std::option::Option<crate::types::Bot>) -> Self {
        self.bot = input;
        self
    }
    /// <p>The bot details.</p>
    pub fn get_bot(&self) -> &::std::option::Option<crate::types::Bot> {
        &self.bot
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
    pub fn build(self) -> crate::operation::create_bot::CreateBotOutput {
        crate::operation::create_bot::CreateBotOutput {
            bot: self.bot,
            _request_id: self._request_id,
        }
    }
}
