// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRoomsInput {
    /// <p>Filters the list to match the specified room name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The first room to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of rooms to return. Default: 50.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Filters the list to match the specified message review handler URI.</p>
    pub message_review_handler_uri: ::std::option::Option<::std::string::String>,
    /// <p>Logging-configuration identifier.</p>
    pub logging_configuration_identifier: ::std::option::Option<::std::string::String>,
}
impl ListRoomsInput {
    /// <p>Filters the list to match the specified room name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The first room to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of rooms to return. Default: 50.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Filters the list to match the specified message review handler URI.</p>
    pub fn message_review_handler_uri(&self) -> ::std::option::Option<&str> {
        self.message_review_handler_uri.as_deref()
    }
    /// <p>Logging-configuration identifier.</p>
    pub fn logging_configuration_identifier(&self) -> ::std::option::Option<&str> {
        self.logging_configuration_identifier.as_deref()
    }
}
impl ListRoomsInput {
    /// Creates a new builder-style object to manufacture [`ListRoomsInput`](crate::operation::list_rooms::ListRoomsInput).
    pub fn builder() -> crate::operation::list_rooms::builders::ListRoomsInputBuilder {
        crate::operation::list_rooms::builders::ListRoomsInputBuilder::default()
    }
}

/// A builder for [`ListRoomsInput`](crate::operation::list_rooms::ListRoomsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRoomsInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) message_review_handler_uri: ::std::option::Option<::std::string::String>,
    pub(crate) logging_configuration_identifier: ::std::option::Option<::std::string::String>,
}
impl ListRoomsInputBuilder {
    /// <p>Filters the list to match the specified room name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the list to match the specified room name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Filters the list to match the specified room name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The first room to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first room to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The first room to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of rooms to return. Default: 50.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of rooms to return. Default: 50.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of rooms to return. Default: 50.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Filters the list to match the specified message review handler URI.</p>
    pub fn message_review_handler_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_review_handler_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the list to match the specified message review handler URI.</p>
    pub fn set_message_review_handler_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_review_handler_uri = input;
        self
    }
    /// <p>Filters the list to match the specified message review handler URI.</p>
    pub fn get_message_review_handler_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_review_handler_uri
    }
    /// <p>Logging-configuration identifier.</p>
    pub fn logging_configuration_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.logging_configuration_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Logging-configuration identifier.</p>
    pub fn set_logging_configuration_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.logging_configuration_identifier = input;
        self
    }
    /// <p>Logging-configuration identifier.</p>
    pub fn get_logging_configuration_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.logging_configuration_identifier
    }
    /// Consumes the builder and constructs a [`ListRoomsInput`](crate::operation::list_rooms::ListRoomsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_rooms::ListRoomsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_rooms::ListRoomsInput {
            name: self.name,
            next_token: self.next_token,
            max_results: self.max_results,
            message_review_handler_uri: self.message_review_handler_uri,
            logging_configuration_identifier: self.logging_configuration_identifier,
        })
    }
}
