// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterGameServerInput {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub game_server_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A custom string that uniquely identifies the game server to register. Game server IDs are developer-defined and must be unique across all game server groups in your Amazon Web Services account.</p>
    pub game_server_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the instance where the game server is running. This ID is available in the instance metadata. EC2 instance IDs use a 17-character format, for example: <code>i-1234567890abcdef0</code>.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Information that is needed to make inbound client connections to the game server. This might include the IP address and port, DNS name, and other information.</p>
    pub connection_info: ::std::option::Option<::std::string::String>,
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub game_server_data: ::std::option::Option<::std::string::String>,
}
impl RegisterGameServerInput {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn game_server_group_name(&self) -> ::std::option::Option<&str> {
        self.game_server_group_name.as_deref()
    }
    /// <p>A custom string that uniquely identifies the game server to register. Game server IDs are developer-defined and must be unique across all game server groups in your Amazon Web Services account.</p>
    pub fn game_server_id(&self) -> ::std::option::Option<&str> {
        self.game_server_id.as_deref()
    }
    /// <p>The unique identifier for the instance where the game server is running. This ID is available in the instance metadata. EC2 instance IDs use a 17-character format, for example: <code>i-1234567890abcdef0</code>.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>Information that is needed to make inbound client connections to the game server. This might include the IP address and port, DNS name, and other information.</p>
    pub fn connection_info(&self) -> ::std::option::Option<&str> {
        self.connection_info.as_deref()
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn game_server_data(&self) -> ::std::option::Option<&str> {
        self.game_server_data.as_deref()
    }
}
impl RegisterGameServerInput {
    /// Creates a new builder-style object to manufacture [`RegisterGameServerInput`](crate::operation::register_game_server::RegisterGameServerInput).
    pub fn builder() -> crate::operation::register_game_server::builders::RegisterGameServerInputBuilder {
        crate::operation::register_game_server::builders::RegisterGameServerInputBuilder::default()
    }
}

/// A builder for [`RegisterGameServerInput`](crate::operation::register_game_server::RegisterGameServerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterGameServerInputBuilder {
    pub(crate) game_server_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) game_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) connection_info: ::std::option::Option<::std::string::String>,
    pub(crate) game_server_data: ::std::option::Option<::std::string::String>,
}
impl RegisterGameServerInputBuilder {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    /// This field is required.
    pub fn game_server_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn set_game_server_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_group_name = input;
        self
    }
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn get_game_server_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_group_name
    }
    /// <p>A custom string that uniquely identifies the game server to register. Game server IDs are developer-defined and must be unique across all game server groups in your Amazon Web Services account.</p>
    /// This field is required.
    pub fn game_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom string that uniquely identifies the game server to register. Game server IDs are developer-defined and must be unique across all game server groups in your Amazon Web Services account.</p>
    pub fn set_game_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_id = input;
        self
    }
    /// <p>A custom string that uniquely identifies the game server to register. Game server IDs are developer-defined and must be unique across all game server groups in your Amazon Web Services account.</p>
    pub fn get_game_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_id
    }
    /// <p>The unique identifier for the instance where the game server is running. This ID is available in the instance metadata. EC2 instance IDs use a 17-character format, for example: <code>i-1234567890abcdef0</code>.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the instance where the game server is running. This ID is available in the instance metadata. EC2 instance IDs use a 17-character format, for example: <code>i-1234567890abcdef0</code>.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The unique identifier for the instance where the game server is running. This ID is available in the instance metadata. EC2 instance IDs use a 17-character format, for example: <code>i-1234567890abcdef0</code>.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>Information that is needed to make inbound client connections to the game server. This might include the IP address and port, DNS name, and other information.</p>
    pub fn connection_info(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_info = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information that is needed to make inbound client connections to the game server. This might include the IP address and port, DNS name, and other information.</p>
    pub fn set_connection_info(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_info = input;
        self
    }
    /// <p>Information that is needed to make inbound client connections to the game server. This might include the IP address and port, DNS name, and other information.</p>
    pub fn get_connection_info(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_info
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn game_server_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn set_game_server_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_data = input;
        self
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn get_game_server_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_data
    }
    /// Consumes the builder and constructs a [`RegisterGameServerInput`](crate::operation::register_game_server::RegisterGameServerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::register_game_server::RegisterGameServerInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::register_game_server::RegisterGameServerInput {
            game_server_group_name: self.game_server_group_name,
            game_server_id: self.game_server_id,
            instance_id: self.instance_id,
            connection_info: self.connection_info,
            game_server_data: self.game_server_data,
        })
    }
}
