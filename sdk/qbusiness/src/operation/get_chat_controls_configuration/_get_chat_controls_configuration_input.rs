// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetChatControlsConfigurationInput {
    /// <p>The identifier of the application for which the chat controls are configured.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of configured chat controls to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If the <code>maxResults</code> response was incomplete because there is more data to retrieve, Amazon Q Business returns a pagination token in the response. You can use this pagination token to retrieve the next set of Amazon Q Business chat controls configured.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetChatControlsConfigurationInput {
    /// <p>The identifier of the application for which the chat controls are configured.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The maximum number of configured chat controls to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If the <code>maxResults</code> response was incomplete because there is more data to retrieve, Amazon Q Business returns a pagination token in the response. You can use this pagination token to retrieve the next set of Amazon Q Business chat controls configured.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetChatControlsConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetChatControlsConfigurationInput`](crate::operation::get_chat_controls_configuration::GetChatControlsConfigurationInput).
    pub fn builder() -> crate::operation::get_chat_controls_configuration::builders::GetChatControlsConfigurationInputBuilder {
        crate::operation::get_chat_controls_configuration::builders::GetChatControlsConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetChatControlsConfigurationInput`](crate::operation::get_chat_controls_configuration::GetChatControlsConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetChatControlsConfigurationInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetChatControlsConfigurationInputBuilder {
    /// <p>The identifier of the application for which the chat controls are configured.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the application for which the chat controls are configured.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the application for which the chat controls are configured.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The maximum number of configured chat controls to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of configured chat controls to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of configured chat controls to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If the <code>maxResults</code> response was incomplete because there is more data to retrieve, Amazon Q Business returns a pagination token in the response. You can use this pagination token to retrieve the next set of Amazon Q Business chat controls configured.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the <code>maxResults</code> response was incomplete because there is more data to retrieve, Amazon Q Business returns a pagination token in the response. You can use this pagination token to retrieve the next set of Amazon Q Business chat controls configured.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the <code>maxResults</code> response was incomplete because there is more data to retrieve, Amazon Q Business returns a pagination token in the response. You can use this pagination token to retrieve the next set of Amazon Q Business chat controls configured.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetChatControlsConfigurationInput`](crate::operation::get_chat_controls_configuration::GetChatControlsConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_chat_controls_configuration::GetChatControlsConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_chat_controls_configuration::GetChatControlsConfigurationInput {
            application_id: self.application_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
